#ifndef BHKPG_H
#define BHKPG_H

#include <stdbool.h>
#include <stddef.h>
#include <signal.h>
#include <sys/types.h>
#include <limits.h>
#include <stdint.h>
#include <setjmp.h>

#define C_CYN "\033[1;36m"
#define C_RED "\033[1;31m"
#define C_YLW "\033[1;33m"
#define C_GRN "\033[1;32m"
#define C_BLD "\033[1m"
#define C_RST "\033[0m"

#define LIKELY(x)   __builtin_expect(!!(x), 1)
#define UNLIKELY(x) __builtin_expect(!!(x), 0)

typedef enum { STATE_UNVISITED, STATE_VISITING, STATE_RESOLVED } ResolveState;

typedef struct
{
  char *name;
  char **patterns;
  size_t pattern_count;
} SubpackageRule;

typedef struct
{
  char *name;
  char *version;
  char *architecture;
  char *type;
  char *license;
  char *repo_origin;
  
  char **sources;
  char **hashes;
  size_t num_sources;
  
  char **dep_names;
  char **dep_constraints;
  size_t dep_count;
  
  char **makedep_names;
  char **makedep_constraints;
  size_t makedep_count;

  /* Virtual Packages, Conflicts, and Rollbacks */
  char **provides;
  size_t provides_count;
  char **conflicts;
  size_t conflicts_count;
  char **obsoletes;
  size_t obsoletes_count;
  
  SubpackageRule *subpackages;
  size_t subpkg_count;
  
  char *build_script;
  char *pre_install;
  char *post_install;
  char *pre_remove;
  char *post_remove;
  
  int install_reason;
  ResolveState state;
  bool is_installed;
  bool is_cached;
  
  bool is_subpackage;
  bool net_access;
  bool is_delta;
  char *base_package_name;
} Package;

typedef struct
{
  Package **pkgs;
  size_t count;
  size_t capacity;
} BuildList;

typedef struct ConflictNode
{
  uint32_t state_hash;
  struct ConflictNode *next;
} ConflictNode;

typedef struct
{
  char name[64];
  char url[256];
  char sig_url[256];
  char pubkey_path[256];
  int priority;
} RepoConfig;

extern int g_verbosity;
extern bool g_pacman_mode;
extern volatile sig_atomic_t g_interrupted;
extern char g_host_arch[32];

extern RepoConfig *g_repos;
extern size_t g_repo_count;

extern char **g_use_flags;
extern size_t g_use_flag_count;

/* OOM Handling and recovery */
extern sigjmp_buf g_oom_env;
extern void *g_oom_pool;
void init_oom_pool (void);

/* version.c */
int bhpkg_vercmp (const char *val, const char *ref);

/* utils.c */
void *xmalloc (size_t size);
void *xrealloc (void *ptr, size_t size);
char *xstrdup (const char *s);
uint64_t fnv1a_hash (const char *str);
bool is_use_flag_enabled (const char *flag);
void print_msg (const char *msg, ...);
void print_err (const char *msg, ...);
void print_warn (const char *msg, ...);
bool safe_exec (char *const argv[]);
bool zero_copy_file (const char *src, const char *dst, mode_t mode);
void package_free (Package *p);

/* graph.c */
void build_list_init (BuildList *list);
void build_list_add (BuildList *list, Package *pkg);
void build_list_free (BuildList *list);
int resolve_dependencies (Package *root, BuildList *build_order);

/* net.c */
int net_download_all (BuildList *list);

/* crypto.c */
bool crypto_hash_file (const char *filepath, char *out_hex);
bool crypto_verify_sha256 (const char *filepath, const char *expected_hash);
bool crypto_verify_signature (const char *filepath, const char *sigpath, const char *pubkey_path);

/* archive.c */
bool archive_extract (const char *filename, const char *dest_dir, int strip_components);
bool archive_compress (const char *src_dir, const char *dest_archive);

/* db.c */
void db_init (void);
void db_rollback (void);
void db_close (void);
bool db_sync_repo (void);
Package *db_fetch_manifest (const char *name, const char *target_version);
Package **db_fetch_all_versions (const char *name, size_t *count_out);
Package **db_fetch_providers (const char *provides_name, size_t *count_out);
void db_register_package (Package *pkg, const char *staging_dir);
bool db_is_required_by_others (const char *pkg_name);
bool db_remove_package (const char *name);
void db_remove_orphans (void);
void db_search (const char *query);
void db_list_installed (void);
void db_get_updates (BuildList *updates);
bool db_check_conflict (const char *filepath, const char *pkg_name, char *owner_out);
bool db_get_file_hash (const char *filepath, char *hash_out);
void db_reconstruct_to_staging (const char *pkg_name, const char *staging_dir);

/* build.c */
bool build_package (Package *pkg);
bool install_artifact (Package *pkg);
void run_hook_script (const char *script_body, const char *hook_name);
void apply_delta_rm_manifest (const char *staging_dir);

/* hook.c */
void hook_execute_all (const char *operation);
void hook_evaluate_triggers (const char *staging_dir);

#endif