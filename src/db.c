#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include <sqlite3.h>
#include <limits.h>
#include "bhpkg.h"

static sqlite3 *db = NULL;
static BuildList pkg_cache;

static sqlite3_stmt *g_insert_file_stmt = NULL;
static const char *g_staging_path = NULL;
static const char *g_package_name = NULL;

void
db_init (void)
{
  int rc;
  rc = sqlite3_open_v2 ("/var/lib/bhpkg/local.db", &db,
                        SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_URI, NULL);
  if (rc != SQLITE_OK)
    {
      fprintf (stderr, "FATAL: Failed to open SQLite DB: %s\n", sqlite3_errmsg (db));
      exit (EXIT_FAILURE);
    }

  sqlite3_exec (db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;", 0, 0, 0);
  sqlite3_exec (db, "CREATE TABLE IF NOT EXISTS local_packages (name TEXT PRIMARY KEY, version TEXT, reason INTEGER);", 0, 0, 0);
  sqlite3_exec (db, "CREATE TABLE IF NOT EXISTS files (package TEXT, filepath TEXT, hash TEXT, is_config INTEGER, UNIQUE(filepath));", 0, 0, 0);

  char view_sql[4096] = "CREATE TEMP VIEW sync_packages AS ";
  bool first = true;

  for (size_t i = 0; i < g_repo_count; i++)
    {
      char attach_sql[512];
      char db_path[PATH_MAX];
      snprintf (db_path, sizeof (db_path), "/var/lib/bhpkg/repo_%s.db", g_repos[i].name);
      
      if (access (db_path, F_OK) == 0)
        {
          snprintf (attach_sql, sizeof (attach_sql), "ATTACH DATABASE '%s' AS repo_%s;", db_path, g_repos[i].name);
          sqlite3_exec (db, attach_sql, 0, 0, 0);

          if (!first)
            strncat (view_sql, " UNION ALL ", sizeof (view_sql) - strlen (view_sql) - 1);
          
          char select_sql[512];
          snprintf (select_sql, sizeof (select_sql), "SELECT '%s' AS origin_repo, %d AS priority, * FROM repo_%s.packages", g_repos[i].name, g_repos[i].priority, g_repos[i].name);
          strncat (view_sql, select_sql, sizeof (view_sql) - strlen (view_sql) - 1);
          
          first = false;
        }
    }
  
  if (!first)
    sqlite3_exec (db, view_sql, 0, 0, 0);

  build_list_init (&pkg_cache);
}

void
db_rollback (void)
{
  if (db)
    sqlite3_exec (db, "ROLLBACK;", 0, 0, 0);
}

bool
db_sync_repo (void)
{
  BuildList sync_list;
  build_list_init (&sync_list);

  print_msg ("Syncing %zu remote repository databases...", g_repo_count);

  for (size_t i = 0; i < g_repo_count; i++)
    {
      Package *p_db = xmalloc (sizeof (Package));
      memset (p_db, 0, sizeof (Package));
      asprintf (&p_db->name, "repo_%s.db", g_repos[i].name);
      p_db->version = xstrdup ("tmp");
      p_db->num_sources = 1;
      p_db->sources = xmalloc (sizeof (char *));
      p_db->sources[0] = xstrdup (g_repos[i].url);

      Package *p_sig = xmalloc (sizeof (Package));
      memset (p_sig, 0, sizeof (Package));
      asprintf (&p_sig->name, "repo_%s.db.sig", g_repos[i].name);
      p_sig->version = xstrdup ("tmp");
      p_sig->num_sources = 1;
      p_sig->sources = xmalloc (sizeof (char *));
      p_sig->sources[0] = xstrdup (g_repos[i].sig_url);

      build_list_add (&sync_list, p_db);
      build_list_add (&sync_list, p_sig);
    }

  if (net_download_all (&sync_list) != 0)
    {
      build_list_free (&sync_list);
      return false;
    }

  for (size_t i = 0; i < g_repo_count; i++)
    {
      char src_db[PATH_MAX], src_sig[PATH_MAX], dst_db[PATH_MAX], dst_sig[PATH_MAX];
      snprintf (src_db, sizeof (src_db), "/var/lib/bhpkg/tmp/repo_%s.db-tmp-0.src", g_repos[i].name);
      snprintf (src_sig, sizeof (src_sig), "/var/lib/bhpkg/tmp/repo_%s.db.sig-tmp-0.src", g_repos[i].name);
      snprintf (dst_db, sizeof (dst_db), "/var/lib/bhpkg/repo_%s.db.tmp", g_repos[i].name);
      snprintf (dst_sig, sizeof (dst_sig), "/var/lib/bhpkg/repo_%s.db.sig.tmp", g_repos[i].name);

      if (!zero_copy_file (src_db, dst_db, 0644) || !zero_copy_file (src_sig, dst_sig, 0644))
        {
          print_err ("Failed to move databases to local storage for repo %s.", g_repos[i].name);
          continue;
        }
        
      unlink (src_db);
      unlink (src_sig);

      if (!crypto_verify_signature (dst_db, dst_sig, g_repos[i].pubkey_path))
        {
          print_err ("Signature verification failed for repo %s! Untrusted database.", g_repos[i].name);
          unlink (dst_db);
          unlink (dst_sig);
          continue;
        }

      char final_db[PATH_MAX];
      snprintf (final_db, sizeof (final_db), "/var/lib/bhpkg/repo_%s.db", g_repos[i].name);
      rename (dst_db, final_db);
      unlink (dst_sig);
      
      print_msg ("Successfully synced repository: %s", g_repos[i].name);
    }

  build_list_free (&sync_list);
  print_msg ("All repositories synchronized successfully.");
  return true;
}

static void
parse_comma_list (const char *str, char ***arr_out, size_t *count_out)
{
  char *copy, *tok;
  size_t count = 0;

  if (!str || !*str)
    {
      *count_out = 0;
      *arr_out = NULL;
      return;
    }
    
  copy = xstrdup (str);
  for (char *c = copy; *c; c++)
    if (*c == ',')
      count++;
      
  count++;
  
  *arr_out = xmalloc (count * sizeof (char *));
  tok = strtok (copy, ",");
  count = 0;
  
  while (tok)
    {
      (*arr_out)[count++] = xstrdup (tok);
      tok = strtok (NULL, ",");
    }
    
  *count_out = count;
  free (copy);
}

/* Optimized conditional dependency parsing using ? syntax (e.g., "wayland?wayland-protocols") */
static void
parse_conditional_deps (const char *str, char ***names_out, char ***constraints_out, size_t *count_out)
{
  char *copy, *tok;
  size_t count = 0;

  if (!str || !*str)
    {
      *count_out = 0;
      *names_out = NULL;
      *constraints_out = NULL;
      return;
    }
    
  copy = xstrdup (str);
  for (char *c = copy; *c; c++)
    if (*c == ' ' || *c == '\t' || *c == ',')
      count++;
      
  count++;
  
  *names_out = xmalloc (count * sizeof (char *));
  *constraints_out = xmalloc (count * sizeof (char *));
  
  tok = strtok (copy, " \t,");
  count = 0;
  
  while (tok)
    {
      char *cond = strchr (tok, '?');
      if (cond)
        {
          *cond = '\0';
          if (!is_use_flag_enabled (tok))
            {
              tok = strtok (NULL, " \t,");
              continue;
            }
          tok = cond + 1;
        }

      char *op = strpbrk (tok, "><=");
      char *dep_name = xstrdup (tok);
      char *constraint = NULL;

      if (op)
        {
          dep_name[op - tok] = '\0';
          constraint = xstrdup (op);
        }
        
      (*names_out)[count] = dep_name;
      (*constraints_out)[count] = constraint;
      count++;
      
      tok = strtok (NULL, " \t,");
    }
    
  *count_out = count;
  free (copy);
}

Package *
db_fetch_manifest (const char *name, const char *target_version)
{
  const char *sql;
  sqlite3_stmt *stmt;
  sqlite3_stmt *chk;
  Package *parsed_pkg = NULL;
  char *best_ver = NULL;

  if (target_version)
    sql = "SELECT version FROM sync_packages WHERE name = ? AND version = ?";
  else
    sql = "SELECT version FROM sync_packages WHERE name = ? ORDER BY priority ASC, version DESC";

  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return NULL;

  sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
  if (target_version)
    sqlite3_bind_text (stmt, 2, target_version, -1, SQLITE_TRANSIENT);

  if (sqlite3_step (stmt) == SQLITE_ROW)
    {
      const char *row_ver = (const char *) sqlite3_column_text (stmt, 0);
      best_ver = xstrdup (row_ver);
    }
  sqlite3_finalize (stmt);

  if (!best_ver)
    return NULL;

  for (size_t i = 0; i < pkg_cache.count; i++)
    {
      if (strcmp (pkg_cache.pkgs[i]->name, name) == 0 && strcmp (pkg_cache.pkgs[i]->version, best_ver) == 0)
        {
          free (best_ver);
          return pkg_cache.pkgs[i];
        }
    }

  sql = "SELECT origin_repo, type, license, sources, hashes, depends, makedepends, build_script, pre_install, post_install, pre_remove, post_remove "
        "FROM sync_packages WHERE name = ? AND version = ? ORDER BY priority ASC LIMIT 1";
        
  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text (stmt, 2, best_ver, -1, SQLITE_TRANSIENT);

      if (sqlite3_step (stmt) == SQLITE_ROW)
        {
          parsed_pkg = xmalloc (sizeof (Package));
          memset (parsed_pkg, 0, sizeof (Package));
          
          parsed_pkg->name = xstrdup (name);
          parsed_pkg->version = xstrdup (best_ver);
          
          const char *orig_col = (const char *) sqlite3_column_text (stmt, 0);
          parsed_pkg->repo_origin = xstrdup (orig_col ? orig_col : "unknown");
          
          const char *type_col = (const char *) sqlite3_column_text (stmt, 1);
          parsed_pkg->type = xstrdup (type_col ? type_col : "source");
          
          const char *lic_col = (const char *) sqlite3_column_text (stmt, 2);
          parsed_pkg->license = xstrdup (lic_col ? lic_col : "Unknown");
          
          parse_comma_list ((const char *) sqlite3_column_text (stmt, 3), &parsed_pkg->sources, &parsed_pkg->num_sources);
          
          size_t hc;
          parse_comma_list ((const char *) sqlite3_column_text (stmt, 4), &parsed_pkg->hashes, &hc);

          parse_conditional_deps ((const char *) sqlite3_column_text (stmt, 5), &parsed_pkg->dep_names, &parsed_pkg->dep_constraints, &parsed_pkg->dep_count);
          parse_conditional_deps ((const char *) sqlite3_column_text (stmt, 6), &parsed_pkg->makedep_names, &parsed_pkg->makedep_constraints, &parsed_pkg->makedep_count);

          const char *b_scr = (const char *) sqlite3_column_text (stmt, 7);
          const char *pre_in = (const char *) sqlite3_column_text (stmt, 8);
          const char *post_in = (const char *) sqlite3_column_text (stmt, 9);
          const char *pre_rm = (const char *) sqlite3_column_text (stmt, 10);
          const char *post_rm = (const char *) sqlite3_column_text (stmt, 11);

          parsed_pkg->build_script = b_scr ? xstrdup (b_scr) : xstrdup ("");
          parsed_pkg->pre_install = pre_in ? xstrdup (pre_in) : xstrdup ("");
          parsed_pkg->post_install = post_in ? xstrdup (post_in) : xstrdup ("");
          parsed_pkg->pre_remove = pre_rm ? xstrdup (pre_rm) : xstrdup ("");
          parsed_pkg->post_remove = post_rm ? xstrdup (post_rm) : xstrdup ("");
          
          parsed_pkg->net_access = false;
          parsed_pkg->is_delta = false;
          parsed_pkg->install_reason = 1;
          parsed_pkg->state = STATE_UNVISITED;

          parsed_pkg->subpkg_count = 2;
          parsed_pkg->subpackages = xmalloc (2 * sizeof (SubpackageRule));
          
          parsed_pkg->subpackages[0].name = xstrdup ("dev");
          parsed_pkg->subpackages[0].pattern_count = 2;
          parsed_pkg->subpackages[0].patterns = xmalloc (2 * sizeof (char *));
          parsed_pkg->subpackages[0].patterns[0] = xstrdup ("usr/include/*");
          parsed_pkg->subpackages[0].patterns[1] = xstrdup ("usr/lib/*.a");
          
          parsed_pkg->subpackages[1].name = xstrdup ("doc");
          parsed_pkg->subpackages[1].pattern_count = 2;
          parsed_pkg->subpackages[1].patterns = xmalloc (2 * sizeof (char *));
          parsed_pkg->subpackages[1].patterns[0] = xstrdup ("usr/share/man/*");
          parsed_pkg->subpackages[1].patterns[1] = xstrdup ("usr/share/doc/*");
        }
      sqlite3_finalize (stmt);
    }

  free (best_ver);
  if (!parsed_pkg)
    return NULL;

  sqlite3_prepare_v2 (db, "SELECT 1 FROM local_packages WHERE name = ?", -1, &chk, NULL);
  sqlite3_bind_text (chk, 1, name, -1, SQLITE_TRANSIENT);
  parsed_pkg->is_installed = (sqlite3_step (chk) == SQLITE_ROW);
  sqlite3_finalize (chk);

  build_list_add (&pkg_cache, parsed_pkg);
  return parsed_pkg;
}

Package **
db_fetch_all_versions (const char *name, size_t *count_out)
{
  const char *sql = "SELECT version FROM sync_packages WHERE name = ? ORDER BY version DESC";
  sqlite3_stmt *stmt;
  Package **list = NULL;
  size_t capacity = 4;
  size_t count = 0;

  list = xmalloc (capacity * sizeof (Package *));

  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
      while (sqlite3_step (stmt) == SQLITE_ROW)
        {
          const char *ver = (const char *) sqlite3_column_text (stmt, 0);
          Package *pkg = db_fetch_manifest (name, ver);
          if (pkg)
            {
              if (count >= capacity)
                {
                  capacity *= 2;
                  list = xrealloc (list, capacity * sizeof (Package *));
                }
              list[count++] = pkg;
            }
        }
      sqlite3_finalize (stmt);
    }
    
  *count_out = count;
  return list;
}

static int
register_file_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  const char *target;
  char hash[65] = { 0 };
  int is_config = 0;

  (void) ftwbuf;
  (void) sb;

  if (typeflag != FTW_F && typeflag != FTW_SL)
    return 0;

  target = fpath + strlen (g_staging_path);
  if (*target == '\0')
    return 0;

  if (strncmp (target, "/etc/", 5) == 0)
    is_config = 1;

  if (typeflag == FTW_F)
    crypto_hash_file (fpath, hash);

  sqlite3_bind_text (g_insert_file_stmt, 1, g_package_name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text (g_insert_file_stmt, 2, target, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text (g_insert_file_stmt, 3, hash[0] ? hash : NULL, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int  (g_insert_file_stmt, 4, is_config);
  
  sqlite3_step (g_insert_file_stmt);
  sqlite3_reset (g_insert_file_stmt);
  return 0;
}

void
db_register_package (Package *pkg, const char *staging_dir)
{
  sqlite3_stmt *stmt;

  sqlite3_exec (db, "BEGIN IMMEDIATE TRANSACTION;", 0, 0, 0);

  sqlite3_prepare_v2 (db, "INSERT OR REPLACE INTO local_packages (name, version, reason) VALUES (?, ?, ?);", -1, &stmt, NULL);
  sqlite3_bind_text (stmt, 1, pkg->name, -1, SQLITE_TRANSIENT);
  sqlite3_bind_text (stmt, 2, pkg->version, -1, SQLITE_TRANSIENT);
  sqlite3_bind_int (stmt, 3, pkg->install_reason);
  sqlite3_step (stmt);
  sqlite3_finalize (stmt);

  sqlite3_prepare_v2 (db, "DELETE FROM files WHERE package = ?;", -1, &stmt, NULL);
  sqlite3_bind_text (stmt, 1, pkg->name, -1, SQLITE_TRANSIENT);
  sqlite3_step (stmt);
  sqlite3_finalize (stmt);

  g_package_name = pkg->name;
  g_staging_path = staging_dir;

  sqlite3_prepare_v2 (db, "INSERT INTO files (package, filepath, hash, is_config) VALUES (?, ?, ?, ?);", -1, &g_insert_file_stmt, NULL);
  nftw (staging_dir, register_file_cb, 20, FTW_PHYS);
  sqlite3_finalize (g_insert_file_stmt);

  sqlite3_exec (db, "COMMIT;", 0, 0, 0);
  pkg->is_installed = true;
}

bool
db_is_required_by_others (const char *pkg_name)
{
  sqlite3_stmt *stmt;
  bool required = false;
  
  if (sqlite3_prepare_v2 (db, "SELECT r.depends, r.makedepends FROM local_packages l JOIN sync_packages r ON l.name = r.name WHERE l.name != ?", -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, pkg_name, -1, SQLITE_TRANSIENT);
      while (sqlite3_step (stmt) == SQLITE_ROW)
        {
          for (int col = 0; col <= 1; col++)
            {
              const char *deps = (const char *) sqlite3_column_text (stmt, col);
              if (!deps)
                continue;
              
              char *copy = xstrdup (deps);
              char *tok = strtok (copy, " \t,");
              
              while (tok)
                {
                  char *cond = strchr (tok, '?');
                  if (cond)
                    {
                      *cond = '\0';
                      if (!is_use_flag_enabled (tok))
                        {
                          tok = strtok (NULL, " \t,");
                          continue;
                        }
                      tok = cond + 1;
                    }
                    
                  char *op = strpbrk (tok, "><=");
                  if (op)
                    *op = '\0';
                    
                  if (strcmp (tok, pkg_name) == 0)
                    {
                      required = true;
                      break;
                    }
                    
                  tok = strtok (NULL, " \t,");
                }
                
              free (copy);
              if (required)
                break;
            }
            
          if (required)
            break;
        }
      sqlite3_finalize (stmt);
    }
  return required;
}

static bool
is_protected_file (const char *filepath)
{
  char resolved[PATH_MAX];
  const char *protected[] = {
    "/bin/sh",
    "/bin/busybox",
    "/bin/bhpkg",
    "/lib/libc.so",
    "/lib/ld-musl-x86_64.so.1",
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/mdev.conf",
    "/etc/horizon/services/syslogd.service",
    "/etc/horizon/services/klogd.service",
    NULL
  };

  if (!realpath (filepath, resolved))
    snprintf (resolved, sizeof (resolved), "%s", filepath);
    
  for (int i = 0; protected[i] != NULL; i++)
    {
      if (strcmp (resolved, protected[i]) == 0)
        return true;
    }
    
  return false;
}

bool
db_remove_package (const char *name)
{
  sqlite3_stmt *stmt;
  Package *pkg = db_fetch_manifest (name, NULL);

  if (db_is_required_by_others (name))
    {
      print_err ("Cannot remove '%s': required by other installed packages.", name);
      return false;
    }

  print_msg ("Removing package %s...", name);
  
  if (pkg && pkg->pre_remove && strlen (pkg->pre_remove) > 0)
    run_hook_script (pkg->pre_remove, "pre_remove");
    
  hook_execute_all ("Remove");

  if (sqlite3_prepare_v2 (db, "SELECT filepath, hash, is_config FROM files WHERE package = ? ORDER BY filepath DESC", -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
      while (sqlite3_step (stmt) == SQLITE_ROW)
        {
          const char *file = (const char *) sqlite3_column_text (stmt, 0);
          const char *db_hash = (const char *) sqlite3_column_text (stmt, 1);
          int is_config = sqlite3_column_int (stmt, 2);

          if (is_protected_file (file))
            {
              print_warn ("Refusing to delete critical system file: %s", file);
              continue;
            }

          if (is_config && db_hash)
            {
              char disk_hash[65] = { 0 };
              crypto_hash_file (file, disk_hash);
              if (strcmp (disk_hash, db_hash) != 0)
                {
                  char *save_path = NULL;
                  asprintf (&save_path, "%s.bhpkg-save", file);
                  if (save_path)
                    {
                      rename (file, save_path);
                      print_warn ("Saved modified configuration as %s", save_path);
                      free (save_path);
                    }
                  continue;
                }
            }

          if (unlink (file) == 0)
            {
              char *pcopy = xstrdup (file);
              char *dir = dirname (pcopy);
              
              while (dir && strcmp (dir, "/") != 0 && strcmp (dir, ".") != 0)
                {
                  if (rmdir (dir) != 0)
                    break;
                  char *next_copy = xstrdup (dir);
                  free (pcopy);
                  pcopy = next_copy;
                  dir = dirname (pcopy);
                }
              free (pcopy);
            }
        }
      sqlite3_finalize (stmt);
    }

  sqlite3_exec (db, "BEGIN IMMEDIATE TRANSACTION;", 0, 0, 0);
  
  sqlite3_prepare_v2 (db, "DELETE FROM files WHERE package = ?", -1, &stmt, NULL);
  sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
  sqlite3_step (stmt);
  sqlite3_finalize (stmt);

  sqlite3_prepare_v2 (db, "DELETE FROM local_packages WHERE name = ?", -1, &stmt, NULL);
  sqlite3_bind_text (stmt, 1, name, -1, SQLITE_TRANSIENT);
  sqlite3_step (stmt);
  sqlite3_finalize (stmt);
  
  sqlite3_exec (db, "COMMIT;", 0, 0, 0);

  if (pkg && pkg->post_remove && strlen (pkg->post_remove) > 0)
    run_hook_script (pkg->post_remove, "post_remove");
    
  print_msg ("Package %s removed cleanly.", name);
  return true;
}

void
db_remove_orphans (void)
{
  sqlite3_stmt *stmt;
  bool removed_any;

  print_msg ("Checking for orphan dependencies...");
  do
    {
      removed_any = false;
      if (sqlite3_prepare_v2 (db, "SELECT name FROM local_packages WHERE reason = 1", -1, &stmt, NULL) == SQLITE_OK)
        {
          char **orphans = NULL;
          size_t count = 0;

          while (sqlite3_step (stmt) == SQLITE_ROW)
            {
              const char *name = (const char *) sqlite3_column_text (stmt, 0);
              if (!db_is_required_by_others (name))
                {
                  orphans = xrealloc (orphans, (count + 1) * sizeof (char *));
                  orphans[count++] = xstrdup (name);
                }
            }
          sqlite3_finalize (stmt);

          for (size_t i = 0; i < count; i++)
            {
              print_msg ("Removing orphan: %s", orphans[i]);
              db_remove_package (orphans[i]);
              free (orphans[i]);
              removed_any = true;
            }
            
          if (orphans)
            free (orphans);
        }
    } while (removed_any);
}

void
db_search (const char *query)
{
  const char *sql = "SELECT name, version, type, license FROM sync_packages WHERE name LIKE ?";
  sqlite3_stmt *stmt;
  char *like_query;
  int found = 0;

  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    {
      print_err ("Search failed. Did you run 'bhpkg -S' to sync the repositories?");
      return;
    }

  like_query = xmalloc (strlen (query) + 3);
  sprintf (like_query, "%%%s%%", query);
  sqlite3_bind_text (stmt, 1, like_query, -1, SQLITE_TRANSIENT);

  printf ("\n%s==> Search results for '%s':%s\n", C_BLD, query, C_RST);
  while (sqlite3_step (stmt) == SQLITE_ROW)
    {
      const char *p_name = (const char *) sqlite3_column_text (stmt, 0);
      const char *p_ver = (const char *) sqlite3_column_text (stmt, 1);
      const char *p_type = (const char *) sqlite3_column_text (stmt, 2);
      const char *p_lic = (const char *) sqlite3_column_text (stmt, 3);
      
      printf ("  %s%s%s %s (%s) [%s]\n", C_CYN, p_name, C_RST, p_ver, p_type ? p_type : "source", p_lic ? p_lic : "Unknown");
      found++;
    }

  if (found == 0)
    printf ("  No packages found matching that query.\n");
    
  printf ("\n");
  sqlite3_finalize (stmt);
  free (like_query);
}

void
db_list_installed (void)
{
  sqlite3_stmt *stmt;
  int count = 0;

  if (sqlite3_prepare_v2 (db, "SELECT name, version FROM local_packages ORDER BY name", -1, &stmt, NULL) != SQLITE_OK)
    return;

  printf ("\n%s==> Installed Packages:%s\n", C_BLD, C_RST);
  while (sqlite3_step (stmt) == SQLITE_ROW)
    {
      const char *p_name = (const char *) sqlite3_column_text (stmt, 0);
      const char *p_ver = (const char *) sqlite3_column_text (stmt, 1);
      printf ("  %s%s%s %s\n", C_GRN, p_name, C_RST, p_ver);
      count++;
    }
    
  printf ("\n  Total: %d packages.\n", count);
  sqlite3_finalize (stmt);
}

void
db_get_updates (BuildList *updates)
{
  sqlite3_stmt *stmt;
  const char *sql = "SELECT l.name, l.version, s.version FROM local_packages l JOIN sync_packages s ON l.name = s.name ORDER BY s.priority ASC";

  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) != SQLITE_OK)
    return;

  while (sqlite3_step (stmt) == SQLITE_ROW)
    {
      const char *name = (const char *) sqlite3_column_text (stmt, 0);
      const char *local_ver = (const char *) sqlite3_column_text (stmt, 1);
      const char *remote_ver = (const char *) sqlite3_column_text (stmt, 2);

      if (bhpkg_vercmp (remote_ver, local_ver) > 0)
        {
          Package *pkg = db_fetch_manifest (name, NULL);
          if (pkg)
            {
              pkg->install_reason = 0;
              build_list_add (updates, pkg);
            }
        }
    }
  sqlite3_finalize (stmt);
}

bool
db_check_conflict (const char *filepath, const char *pkg_name, char *owner_out)
{
  sqlite3_stmt *stmt;
  bool conflict = false;
  const char *sql = "SELECT package FROM files WHERE filepath = ? AND package != ?";

  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, filepath, -1, SQLITE_TRANSIENT);
      sqlite3_bind_text (stmt, 2, pkg_name, -1, SQLITE_TRANSIENT);

      if (sqlite3_step (stmt) == SQLITE_ROW)
        {
          const char *owner = (const char *) sqlite3_column_text (stmt, 0);
          if (owner_out && owner)
            snprintf (owner_out, 256, "%s", owner);
          conflict = true;
        }
      sqlite3_finalize (stmt);
    }
  return conflict;
}

bool
db_get_file_hash (const char *filepath, char *hash_out)
{
  sqlite3_stmt *stmt;
  bool found = false;
  
  if (sqlite3_prepare_v2 (db, "SELECT hash FROM files WHERE filepath = ?", -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, filepath, -1, SQLITE_TRANSIENT);
      if (sqlite3_step (stmt) == SQLITE_ROW)
        {
          const char *h = (const char *) sqlite3_column_text (stmt, 0);
          if (h)
            snprintf (hash_out, 65, "%s", h);
          found = true;
        }
      sqlite3_finalize (stmt);
    }
  return found;
}

void
db_reconstruct_to_staging (const char *pkg_name, const char *staging_dir)
{
  sqlite3_stmt *stmt;
  const char *sql = "SELECT filepath FROM files WHERE package = ?";
  
  if (sqlite3_prepare_v2 (db, sql, -1, &stmt, NULL) == SQLITE_OK)
    {
      sqlite3_bind_text (stmt, 1, pkg_name, -1, SQLITE_TRANSIENT);
      while (sqlite3_step (stmt) == SQLITE_ROW)
        {
          const char *file = (const char *) sqlite3_column_text (stmt, 0);
          if (file)
            {
              char target[PATH_MAX];
              snprintf (target, sizeof (target), "%s%s", staging_dir, file);
              
              char tmp[PATH_MAX];
              snprintf (tmp, sizeof (tmp), "%s", target);
              for (char *p = tmp + 1; *p; p++)
                {
                  if (*p == '/')
                    {
                      *p = '\0';
                      mkdir (tmp, 0755);
                      *p = '/';
                    }
                }
              
              link (file, target);
            }
        }
      sqlite3_finalize (stmt);
    }
}

void
db_close (void)
{
  for (size_t i = 0; i < pkg_cache.count; i++)
    package_free (pkg_cache.pkgs[i]);
    
  build_list_free (&pkg_cache);
  
  if (db)
    sqlite3_close (db);
}