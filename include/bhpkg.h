#ifndef BHPKG_H
#define BHPKG_H

#include <stdbool.h>
#include <stddef.h>
#include <limits.h>
#include <signal.h>
#include <sys/types.h>

#define STATE_UNVISITED 0
#define STATE_VISITING  1
#define STATE_RESOLVED  2

#define REPO_URL "http://127.0.0.1:8000/sync.db"
#define REPO_SIG_URL "http://127.0.0.1:8000/sync.db.sig"
#define PUBKEY_PATH "/etc/bhpkg/repo-pub.pem"
#define SSL_CERT_PATH "/etc/ssl/certs/ca-certificates.crt"

#define C_RST  "\033[0m"
#define C_BLD  "\033[1m"
#define C_CYN  "\033[1;36m"
#define C_GRN  "\033[1;32m"
#define C_RED  "\033[1;31m"
#define C_YLW  "\033[1;33m"

extern volatile sig_atomic_t g_interrupted;

typedef struct Package {
    char *name;
    char *version;
    char *source_url;
    char *sha256;
    
    char *build_script;
    char *pre_install;
    char *post_install;
    
    int state;               
    size_t dep_count;
    char **dep_names;
    char **dep_constraints; 
    struct Package **deps;   
    
    bool is_cached;
    bool is_installed;
    int install_reason; // 0 = Explicit, 1 = Dependency
} Package;

typedef struct {
    Package **pkgs;
    size_t count;
    size_t capacity;
} BuildList;

void *xmalloc(size_t size);
void *xrealloc(void *ptr, size_t size);
char *xstrdup(const char *s);
void print_msg(const char *msg, ...);
void print_err(const char *msg, ...);
void print_warn(const char *msg, ...);
bool safe_exec(char *const argv[]);
bool zero_copy_file(const char *src, const char *dst, mode_t mode);

void build_list_init(BuildList *list);
void build_list_add(BuildList *list, Package *pkg);
void build_list_free(BuildList *list);
int resolve_dependencies(Package *pkg, BuildList *build_order);

void db_init(void);
void db_close(void);
bool db_sync_repo(void);
Package* db_fetch_manifest(const char *name);
void db_register_package(Package *pkg, const char *staging_dir);
bool db_remove_package(const char *name);
void db_get_updates(BuildList *updates);
void db_list_installed(void);
void db_search(const char *query);
bool db_check_conflict(const char *filepath, const char *pkg_name, char *owner_out);
void db_rollback(void);

int net_download_all(BuildList *download_list);
bool crypto_verify_sha256(const char *filepath, const char *expected_hash);
bool crypto_verify_signature(const char *filepath, const char *sigpath, const char *pubkey);
bool archive_extract(const char *archive, const char *dest_dir);
bool archive_compress(const char *src_dir, const char *dest_archive);
bool build_package(Package *pkg);
bool install_artifact(Package *pkg);
void cache_prune(void);

#endif