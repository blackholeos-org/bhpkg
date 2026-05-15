#ifndef BHPKG_H
#define BHPKG_H

#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

#ifndef O_NOATIME
#define O_NOATIME 0
#endif

#define STATE_UNVISITED 0
#define STATE_VISITING  1
#define STATE_RESOLVED  2

#define C_RST  "\033[0m"
#define C_BLD  "\033[1m"
#define C_CYN  "\033[1;36m"
#define C_GRN  "\033[1;32m"
#define C_RED  "\033[1;31m"
#define C_YLW  "\033[1;33m"

extern volatile sig_atomic_t g_interrupted;

extern char g_repo_url[256];
extern char g_repo_sig_url[256];
extern char g_pubkey_path[256];

extern int g_verbosity;
extern bool g_pacman_mode;

typedef struct Package {
  char *name;
  char *version;
  char *type;
  char *license;
  char **sources;
  char **hashes;
  size_t num_sources;
  
  char *build_script;
  char *pre_install;
  char *post_install;
  char *pre_remove;
  char *post_remove;
  
  int state;
  size_t dep_count;
  size_t makedep_count;
  char **dep_names;
  char **dep_constraints;
  char **makedep_names;
  char **makedep_constraints;
  
  bool is_cached;
  bool is_installed;
  int install_reason;
} Package;

typedef struct {
  Package **pkgs;
  size_t count;
  size_t capacity;
} BuildList;

void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
char *xstrdup (const char *s);
void print_msg (const char *msg, ...);
void print_err (const char *msg, ...);
void print_warn (const char *msg, ...);
bool safe_exec (char *const argv[]);
bool zero_copy_file (const char *src, const char *dst, mode_t mode);
void package_free (Package *p);

void config_load (void);
void run_hook (const char *script_body, const char *hook_name);

void build_list_init (BuildList *list);
void build_list_add (BuildList *list, Package *pkg);
void build_list_free (BuildList *list);
int resolve_dependencies (Package *pkg, BuildList *build_order);

void db_init (void);
void db_close (void);
bool db_sync_repo (void);
Package *db_fetch_manifest (const char *name, const char *target_version);
Package **db_fetch_all_versions (const char *name, size_t *count_out);
void db_register_package (Package *pkg, const char *staging_dir);
bool db_remove_package (const char *name);
void db_remove_orphans (void);
void db_get_updates (BuildList *updates);
void db_list_installed (void);
void db_search (const char *query);
bool db_check_conflict (const char *filepath, const char *pkg_name, char *owner_out);
bool db_get_file_hash (const char *filepath, char *hash_out);
bool db_is_required_by_others (const char *pkg_name);
void db_rollback (void);

int net_download_all (BuildList *download_list);
bool crypto_verify_sha256 (const char *filepath, const char *expected_hash);
bool crypto_verify_signature (const char *filepath, const char *sigpath, const char *pubkey);
bool crypto_hash_file (const char *filepath, char *out_hex);
bool archive_extract (const char *archive, const char *dest_dir, int strip_components);
bool archive_compress (const char *src_dir, const char *dest_archive);
bool build_package (Package *pkg);
bool install_artifact (Package *pkg);
void cache_prune (void);

#endif