#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <ctype.h>
#include "bhpkg.h"

volatile sig_atomic_t g_interrupted = 0;

int g_verbosity = 1;
bool g_pacman_mode = false;
char g_host_arch[32];

RepoConfig *g_repos = NULL;
size_t g_repo_count = 0;

char **g_use_flags = NULL;
size_t g_use_flag_count = 0;

static void
strip_whitespace (char *str)
{
  char *p = str;
  int l = strlen (p);
  while (l > 0 && isspace ((unsigned char)p[l - 1])) p[--l] = '\0';
  while (isspace ((unsigned char)*p)) p++;
  if (p != str) memmove (str, p, l + 1);
}

void
config_load (void)
{
  FILE *f = fopen ("/etc/bhpkg/bhpkg.conf", "re");
  char *line = NULL;
  size_t len = 0;
  char current_section[64] = {0};
  
  if (UNLIKELY (!f)) return;

  while (getline (&line, &len, f) != -1)
    {
      strip_whitespace (line);
      if (line[0] == '#' || line[0] == ';' || line[0] == '\0') continue;
      
      if (line[0] == '[' && line[strlen (line) - 1] == ']')
        {
          strncpy (current_section, line + 1, sizeof (current_section) - 1);
          current_section[strlen (current_section) - 1] = '\0';
          
          if (strncmp (current_section, "repo:", 5) == 0)
            {
              g_repos = xrealloc (g_repos, (g_repo_count + 1) * sizeof (RepoConfig));
              memset (&g_repos[g_repo_count], 0, sizeof (RepoConfig));
              strncpy (g_repos[g_repo_count].name, current_section + 5, sizeof (g_repos[0].name) - 1);
              g_repos[g_repo_count].priority = 99;
              g_repo_count++;
            }
          continue;
        }
        
      char *eq = strchr (line, '=');
      if (!eq) continue;
      *eq = '\0';
      
      char *key = line;
      char *val = eq + 1;
      strip_whitespace (key);
      strip_whitespace (val);
      
      if (val[0] == '"' && val[strlen (val) - 1] == '"')
        {
          val[strlen (val) - 1] = '\0';
          val++;
        }
      
      if (strcmp (current_section, "options") == 0)
        {
          if (strcmp (key, "VERBOSITY") == 0) g_verbosity = atoi (val);
          else if (strcmp (key, "PACMAN_MODE") == 0) g_pacman_mode = (strcmp (val, "true") == 0);
          else if (strcmp (key, "USE") == 0)
            {
              char *tok = strtok (val, " \t");
              while (tok)
                {
                  g_use_flags = xrealloc (g_use_flags, (g_use_flag_count + 1) * sizeof (char *));
                  g_use_flags[g_use_flag_count++] = xstrdup (tok);
                  tok = strtok (NULL, " \t");
                }
            }
        }
      else if (strncmp (current_section, "repo:", 5) == 0)
        {
          RepoConfig *r = &g_repos[g_repo_count - 1];
          if (strcmp (key, "URL") == 0) strncpy (r->url, val, sizeof (r->url) - 1);
          else if (strcmp (key, "SIG") == 0) strncpy (r->sig_url, val, sizeof (r->sig_url) - 1);
          else if (strcmp (key, "PUBKEY") == 0) strncpy (r->pubkey_path, val, sizeof (r->pubkey_path) - 1);
          else if (strcmp (key, "PRIORITY") == 0) r->priority = atoi (val);
        }
    }
  free (line);
  fclose (f);
}

void
handle_signal (int sig)
{
  (void) sig;
  g_interrupted = 1;
  print_err ("Interrupt caught. Safely halting operations...");
}

void
print_help (void)
{
  printf ("\n%sBlackhole Package Manager (bhpkg)%s\n", C_BLD, C_RST);
  printf ("  -S, --sync          Sync repository databases\n");
  printf ("  -i, --install <pkg> Install a package explicitly\n");
  printf ("  -u, --update        Update entire system (or specific package)\n");
  printf ("  -R, --remove  <pkg> Remove a package cleanly\n");
  printf ("  -Rs <pkg>           Remove package and orphaned dependencies\n");
  printf ("  -Yc                 Remove all unneeded orphan packages globally\n");
  printf ("  -Ss <query>         Search online repositories\n");
  printf ("  -Q                  List installed packages\n");
  printf ("  -Sc                 Clean cache directory\n\n");
  printf ("  -v, -vv, -vvv       Increase verbosity up to Debug/Trace logs\n");
  printf ("  -q, --quiet         Silent mode (Verbosity Level 0)\n\n");
}

void
cache_prune (void)
{
  DIR *dir;
  struct dirent *ent;
  int count = 0;

  print_msg ("Cleaning cache directory (/var/cache/bhpkg)...");
  dir = opendir ("/var/cache/bhpkg");
  if (!dir) return;

  while ((ent = readdir (dir)) != NULL)
    {
      if (ent->d_type == DT_REG)
        {
          char path[PATH_MAX];
          snprintf (path, sizeof (path), "/var/cache/bhpkg/%s", ent->d_name);
          if (unlink (path) == 0) count++;
        }
    }
  closedir (dir);
  print_msg ("Removed %d cached artifacts.", count);
}

void
process_build_queue (BuildList *order)
{
  BuildList to_download;
  build_list_init (&to_download);

  for (size_t i = 0; i < order->count; i++)
    {
      Package *p = order->pkgs[i];
      char cache_path[PATH_MAX];
      snprintf (cache_path, sizeof (cache_path), "/var/cache/bhpkg/%s-%s.tar.zst", p->name, p->version);

      if (access (cache_path, F_OK) == 0)
        p->is_cached = true;
      if (!p->is_installed && !p->is_cached)
        build_list_add (&to_download, p);
    }

  if (to_download.count > 0)
    {
      if (net_download_all (&to_download) != 0 || g_interrupted)
        goto build_cleanup;
    }

  for (size_t i = 0; i < order->count; i++)
    {
      Package *p;
      Package *old_p;

      if (g_interrupted) break;
      p = order->pkgs[i];

      if (p->is_installed)
        {
          if (g_verbosity >= 1)
            printf ("  %s[SKIP]%s %s is already up to date.\n", C_GRN, C_RST, p->name);
          continue;
        }

      print_msg ("Processing [%s%s%s]", C_YLW, p->name, C_RST);

      if (!p->is_cached && !build_package (p))
        {
          print_err ("Build failed for %s.", p->name);
          exit (EXIT_FAILURE);
        }

      old_p = db_fetch_manifest (p->name, NULL);
      if (old_p && old_p->is_installed)
        print_warn ("Upgrading existing package: %s", p->name);

      if (!install_artifact (p))
        {
          print_err ("Install failed for %s.", p->name);
          exit (EXIT_FAILURE);
        }
    }

build_cleanup:
  build_list_free (&to_download);
}

static void
detect_architecture (void)
{
  struct utsname buffer;
  if (uname (&buffer) != 0)
    {
      print_err ("Failed to detect system architecture. Defaulting to x86_64.");
      strncpy (g_host_arch, "x86_64", 31);
    }
  else
    {
      strncpy (g_host_arch, buffer.machine, 31);
    }
}

int
main (int argc, char **argv)
{
  bool do_sync = false, do_install = false, do_update = false, do_remove = false;
  bool do_orphans = false, do_cache = false, do_search = false, do_list = false;
  char *pkg_target = NULL;
  char *search_query = NULL;

  if (argc < 2)
    {
      print_help ();
      return 0;
    }

  if (geteuid () != 0)
    {
      print_err ("bhpkg must be run as root to modify the system.");
      return 1;
    }

  detect_architecture ();
  init_oom_pool ();

  /* Wrap the entire execution in an Emergency Block. 
     in case memory fails inside the solver or DB, xmalloc() throws us back here cleanly. */
  if (sigsetjmp (g_oom_env, 1) != 0)
    {
      print_err ("Package transaction aborted safely due to Out-Of-Memory.");
      db_rollback ();
      return EXIT_FAILURE;
    }

  config_load ();

  signal (SIGINT, handle_signal);
  signal (SIGTERM, handle_signal);

  chmod ("/var", 0755);
  chmod ("/var/lib", 0755);

  mkdir ("/var/lib/bhpkg", 0755);
  mkdir ("/var/lib/bhpkg/tmp", 0777);
  mkdir ("/var/cache/bhpkg", 0755);
  mkdir ("/etc/bhpkg", 0755);
  
  chmod ("/var/lib/bhpkg", 0755);
  chmod ("/var/lib/bhpkg/tmp", 0777);

  db_init ();

  for (int i = 1; i < argc; i++)
    {
      if (argv[i][0] == '-' && argv[i][1] != '-')
        {
          for (int j = 1; argv[i][j]; j++)
            {
              switch (argv[i][j])
                {
                  case 'S': do_sync = true; break;
                  case 'y': do_sync = true; break;
                  case 'u': do_update = true; break;
                  case 'i': do_install = true; break;
                  case 'R': do_remove = true; break;
                  case 'v': 
                    g_verbosity++;
                    if (g_verbosity > 3) g_verbosity = 3;
                    break;
                  case 'q': g_verbosity = 0; break;
                  case 's': 
                    if (do_remove) do_orphans = true;
                    if (do_sync) { do_search = true; do_sync = false; }
                    break;
                  case 'c':
                    if (do_sync) { do_cache = true; do_sync = false; }
                    break;
                  case 'Q': do_list = true; break;
                  case 'Y': 
                    if (argv[i][j+1] == 'c') { do_orphans = true; j++; }
                    break;
                }
            }
          if ((do_install || do_update || do_remove || do_search) && !pkg_target && i + 1 < argc && argv[i+1][0] != '-')
            {
              if (do_search) search_query = argv[++i];
              else pkg_target = argv[++i];
            }
        }
      else if (strcmp (argv[i], "--sync") == 0) do_sync = true;
      else if (strcmp (argv[i], "--install") == 0) do_install = true;
      else if (strcmp (argv[i], "--update") == 0) do_update = true;
      else if (strcmp (argv[i], "--remove") == 0) do_remove = true;
      else if (strcmp (argv[i], "--verbose") == 0) { g_verbosity++; if (g_verbosity > 3) g_verbosity = 3; }
      else if (strcmp (argv[i], "--quiet") == 0) g_verbosity = 0;
      else
        {
          if (!pkg_target && !do_search) pkg_target = argv[i];
          else if (!search_query && do_search) search_query = argv[i];
        }
    }

  if (do_cache) cache_prune ();
  if (do_orphans && !do_remove) db_remove_orphans ();
  
  if (do_sync)
    {
      if (!db_sync_repo ())
        {
          db_close ();
          return 1;
        }
    }

  if (do_search && search_query) db_search (search_query);
  if (do_list) db_list_installed ();
  
  if (do_remove && pkg_target)
    {
      if (db_remove_package (pkg_target) && do_orphans)
        db_remove_orphans ();
    }

  if (do_update)
    {
      BuildList up;
      build_list_init (&up);

      if (pkg_target)
        {
          Package *pkg = db_fetch_manifest (pkg_target, NULL);
          if (!pkg || !pkg->is_installed)
            print_err ("Package '%s' not found locally.", pkg_target);
          else
            {
              pkg->install_reason = 0;
              build_list_add (&up, pkg);
            }
        }
      else db_get_updates (&up);

      if (up.count == 0 && !pkg_target) print_msg ("System is fully up-to-date.");
      else if (up.count > 0)
        {
          print_msg ("System upgrade triggered. Processing %zu packages...", up.count);
          for (size_t i = 0; i < up.count; i++)
            {
              BuildList order;
              if (g_interrupted) break;
              build_list_init (&order);
              resolve_dependencies (up.pkgs[i], &order);
              process_build_queue (&order);
              build_list_free (&order);
            }
        }
      build_list_free (&up);
    }

  if (do_install && pkg_target)
    {
      BuildList order;
      Package *pkg = db_fetch_manifest (pkg_target, NULL);
      if (!pkg)
        {
          print_err ("Package '%s' not found in sync database!", pkg_target);
          db_close ();
          return 1;
        }
      pkg->install_reason = 0;
      build_list_init (&order);
      resolve_dependencies (pkg, &order);
      process_build_queue (&order);
      build_list_free (&order);
    }

  if (!do_sync && !do_install && !do_update && !do_remove && !do_orphans && !do_cache && !do_search && !do_list)
    print_help ();

  db_close ();
  return 0;
}