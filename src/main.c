#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <ctype.h>
#include "bhpkg.h"

volatile sig_atomic_t g_interrupted = 0;

char g_repo_url[256] = "https://repo.blackhole-os.org/sync.db";
char g_repo_sig_url[256] = "https://repo.blackhole-os.org/sync.db.sig";
char g_pubkey_path[256] = "/etc/bhpkg/repo-pub.pem";

void
config_load (void)
{
  FILE *f = fopen ("/etc/bhpkg/bhpkg.conf", "re");
  char *line = NULL;
  size_t len = 0;
  
  if (!f) return;

  while (getline (&line, &len, f) != -1)
    {
      char *eq;
      char *p = line;
      char *k_end;
      
      while (isspace ((unsigned char)*p)) p++;
      
      if (*p == '#' || *p == ';' || *p == '\0' || *p == '\n') 
        continue;
      
      eq = strchr (p, '=');
      if (!eq) continue;
      
      *eq = '\0';
      
      k_end = eq - 1;
      while (k_end > p && isspace ((unsigned char)*k_end))
        {
          *k_end = '\0';
          k_end--;
        }
      
      char *val = eq + 1;
      while (isspace ((unsigned char)*val)) val++;
      val[strcspn (val, "\r\n")] = '\0';
      
      if (strcmp (p, "REPO_URL") == 0)
        snprintf (g_repo_url, sizeof (g_repo_url), "%s", val);
      else if (strcmp (p, "REPO_SIG_URL") == 0)
        snprintf (g_repo_sig_url, sizeof (g_repo_sig_url), "%s", val);
      else if (strcmp (p, "PUBKEY_PATH") == 0)
        snprintf (g_pubkey_path, sizeof (g_pubkey_path), "%s", val);
      else if (strcmp (p, "PACMAN_MODE") == 0)
        g_pacman_mode = (strcmp (val, "true") == 0 || strcmp (val, "1") == 0);
      else if (strcmp (p, "VERBOSITY") == 0)
        g_verbosity = atoi (val);
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
  printf ("  -S, --sync          Sync repository database\n");
  printf ("  -i, --install <pkg> Install a package explicitly\n");
  printf ("  -u, --update        Update entire system (or specific package)\n");
  printf ("  -R, --remove  <pkg> Remove a package cleanly\n");
  printf ("  -Rs <pkg>           Remove package and orphaned dependencies\n");
  printf ("  -Yc                 Remove all unneeded orphan packages globally\n");
  printf ("  -Ss <query>         Search online repository\n");
  printf ("  -Q                  List installed packages\n");
  printf ("  -Sc                 Clean cache directory\n\n");
  printf ("  -v, -vv, -vvv       Increase verbosity up to Debug/Trace logs\n");
  printf ("  -q, --quiet         Silent mode (Verbosity Level 0)\n\n");
  printf ("  Flags can be combined fluidly (e.g., bhpkg -Syu or bhpkg -Si <pkg>)\n\n");
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

      print_msg ("Verifying SHA256 cryptographic hashes...");
      for (size_t i = 0; i < to_download.count; i++)
        {
          for (size_t j = 0; j < to_download.pkgs[i]->num_sources; j++)
            {
              char fn[PATH_MAX];
              snprintf (fn, sizeof (fn), "/var/lib/bhpkg/tmp/%s-%s-%zu.src",
                        to_download.pkgs[i]->name, to_download.pkgs[i]->version, j);

              if (!crypto_verify_sha256 (fn, to_download.pkgs[i]->hashes[j]))
                {
                  print_err ("Integrity check failed for %s! Potential MITM attack.", to_download.pkgs[i]->name);
                  exit (EXIT_FAILURE);
                }
            }
          if (g_verbosity >= 1)
            printf ("  %s[PASS]%s %s\n", C_GRN, C_RST, to_download.pkgs[i]->name);
        }
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

  /* Command Pipeline Parsing */
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

  /* Command Execution Sequence */
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
          print_err ("Package '%s' not found in sync.db!", pkg_target);
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