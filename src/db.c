#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ftw.h>
#include <libgen.h>
#include <sqlite3.h>
#include "bhpkg.h"

static sqlite3 *db = NULL;
static BuildList pkg_cache;

static sqlite3_stmt *g_insert_file_stmt = NULL;
static const char *g_staging_path = NULL;
static const char *g_package_name = NULL;

void db_init(void) {
    int rc = sqlite3_open("/var/lib/bhpkg/local.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "FATAL: Failed to open SQLite DB: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    sqlite3_exec(db, "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA foreign_keys=ON;", 0, 0, 0);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS local_packages (name TEXT PRIMARY KEY, version TEXT, reason INTEGER);", 0, 0, 0);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS files (package TEXT, filepath TEXT, UNIQUE(filepath));", 0, 0, 0);
    
    if (access("/var/lib/bhpkg/sync.db", F_OK) == 0) {
        sqlite3_exec(db, "ATTACH DATABASE '/var/lib/bhpkg/sync.db' AS sync;", 0, 0, 0);
    }
    
    build_list_init(&pkg_cache);
}

void db_rollback(void) { 
    if (db) sqlite3_exec(db, "ROLLBACK;", 0, 0, 0); 
}

bool db_sync_repo(void) {
    print_msg("Syncing remote repository databases...");
    BuildList sync_list; 
    build_list_init(&sync_list);
    
    Package p_db = { .name="sync.db", .version="tmp", .source_url=REPO_URL };
    Package p_sig = { .name="sync.db.sig", .version="tmp", .source_url=REPO_SIG_URL };
    build_list_add(&sync_list, &p_db); 
    build_list_add(&sync_list, &p_sig);
    
    if (net_download_all(&sync_list) != 0) { 
        build_list_free(&sync_list); 
        return false; 
    }
    build_list_free(&sync_list);
    
    rename("/tmp/sync.db-tmp.tar.gz", "/var/lib/bhpkg/sync.db.tmp");
    rename("/tmp/sync.db.sig-tmp.tar.gz", "/var/lib/bhpkg/sync.db.sig.tmp");

    if (!crypto_verify_signature("/var/lib/bhpkg/sync.db.tmp", "/var/lib/bhpkg/sync.db.sig.tmp", PUBKEY_PATH)) {
        print_err("Repository signature verification failed! Untrusted database.");
        unlink("/var/lib/bhpkg/sync.db.tmp"); 
        unlink("/var/lib/bhpkg/sync.db.sig.tmp");
        return false;
    }

    rename("/var/lib/bhpkg/sync.db.tmp", "/var/lib/bhpkg/sync.db");
    unlink("/var/lib/bhpkg/sync.db.sig.tmp");
    
    sqlite3_exec(db, "DETACH DATABASE sync;", 0, 0, 0);
    int rc = sqlite3_exec(db, "ATTACH DATABASE '/var/lib/bhpkg/sync.db' AS sync;", 0, 0, 0);
    if (rc != SQLITE_OK) {
        print_err("Failed to attach sync.db: %s", sqlite3_errmsg(db));
        return false;
    }
    
    print_msg("Repository synchronized successfully.");
    return true;
}

Package* db_fetch_manifest(const char *name) {
    for (size_t i = 0; i < pkg_cache.count; i++) {
        if (strcmp(pkg_cache.pkgs[i]->name, name) == 0) return pkg_cache.pkgs[i];
    }

    const char *sql = "SELECT version, source_url, sha256, depends, build_script, pre_install, post_install FROM sync.packages WHERE name = ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return NULL;
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);

    if (sqlite3_step(stmt) != SQLITE_ROW) { 
        sqlite3_finalize(stmt); 
        return NULL; 
    }

    Package *pkg = xmalloc(sizeof(Package)); 
    memset(pkg, 0, sizeof(Package));
    pkg->name = xstrdup(name);
    pkg->version = xstrdup((const char*)sqlite3_column_text(stmt, 0));
    pkg->source_url = xstrdup((const char*)sqlite3_column_text(stmt, 1));
    pkg->sha256 = xstrdup((const char*)sqlite3_column_text(stmt, 2));
    
    const char *b_scr = (const char*)sqlite3_column_text(stmt, 4);
    const char *pre = (const char*)sqlite3_column_text(stmt, 5);
    const char *post = (const char*)sqlite3_column_text(stmt, 6);
    pkg->build_script = b_scr ? xstrdup(b_scr) : xstrdup("");
    pkg->pre_install = pre ? xstrdup(pre) : xstrdup("");
    pkg->post_install = post ? xstrdup(post) : xstrdup("");
    pkg->install_reason = 1;

    sqlite3_stmt *chk;
    sqlite3_prepare_v2(db, "SELECT 1 FROM local_packages WHERE name = ?", -1, &chk, NULL);
    sqlite3_bind_text(chk, 1, name, -1, SQLITE_TRANSIENT);
    pkg->is_installed = (sqlite3_step(chk) == SQLITE_ROW);
    sqlite3_finalize(chk);

    build_list_add(&pkg_cache, pkg); 

    const char *deps_str = (const char*)sqlite3_column_text(stmt, 3);
    if (deps_str && strlen(deps_str) > 0) {
        char *deps_copy = xstrdup(deps_str);
        size_t count = 1; 
        for (char *c = deps_copy; *c; c++) if (*c == ',') count++;
        
        pkg->dep_names = xmalloc(count * sizeof(char*));
        pkg->dep_constraints = xmalloc(count * sizeof(char*));
        pkg->deps = xmalloc(count * sizeof(Package*));
        
        char *token = strtok(deps_copy, ",");
        while (token) {
            char *op = strpbrk(token, "><=");
            char *dep_name = xstrdup(token);
            char *constraint = NULL;
            if (op) { 
                dep_name[op - token] = '\0'; 
                constraint = xstrdup(op); 
            }
            pkg->dep_names[pkg->dep_count] = dep_name;
            pkg->dep_constraints[pkg->dep_count] = constraint;
            pkg->deps[pkg->dep_count] = db_fetch_manifest(dep_name);
            pkg->dep_count++;
            token = strtok(NULL, ",");
        }
        free(deps_copy);
    }
    sqlite3_finalize(stmt); 
    return pkg;
}

static int register_file_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf; (void)sb; 
    if (typeflag != FTW_F && typeflag != FTW_SL) return 0;
    
    const char *target = fpath + strlen(g_staging_path);
    if (*target == '\0') return 0;
    
    sqlite3_bind_text(g_insert_file_stmt, 1, g_package_name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(g_insert_file_stmt, 2, target, -1, SQLITE_TRANSIENT);
    sqlite3_step(g_insert_file_stmt);
    sqlite3_reset(g_insert_file_stmt);
    return 0;
}

void db_register_package(Package *pkg, const char *staging_dir) {
    sqlite3_exec(db, "BEGIN EXCLUSIVE TRANSACTION;", 0, 0, 0);
    
    sqlite3_stmt *stmt;
    sqlite3_prepare_v2(db, "INSERT OR REPLACE INTO local_packages (name, version, reason) VALUES (?, ?, ?);", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, pkg->name, -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, pkg->version, -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 3, pkg->install_reason);
    sqlite3_step(stmt); 
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "DELETE FROM files WHERE package = ?;", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, pkg->name, -1, SQLITE_TRANSIENT);
    sqlite3_step(stmt); 
    sqlite3_finalize(stmt);

    g_package_name = pkg->name; 
    g_staging_path = staging_dir;
    
    sqlite3_prepare_v2(db, "INSERT INTO files (package, filepath) VALUES (?, ?);", -1, &g_insert_file_stmt, NULL);
    nftw(staging_dir, register_file_cb, 20, FTW_PHYS);
    sqlite3_finalize(g_insert_file_stmt);
    
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    pkg->is_installed = true;
}

bool db_remove_package(const char *name) {
    sqlite3_stmt *stmt;
    
    sqlite3_prepare_v2(db, "SELECT l.name, r.depends FROM local_packages l JOIN sync.packages r ON l.name = r.name", -1, &stmt, NULL);
    bool blocked = false;
    while(sqlite3_step(stmt) == SQLITE_ROW) {
        const char *l_name = (const char*)sqlite3_column_text(stmt, 0);
        const char *deps = (const char*)sqlite3_column_text(stmt, 1);
        if (strcmp(l_name, name) == 0 || !deps) continue;
        
        char *deps_copy = xstrdup(deps);
        char *tok = strtok(deps_copy, ",");
        while(tok) {
            char *op = strpbrk(tok, "><="); 
            if (op) *op = '\0';
            if (strcmp(tok, name) == 0) {
                print_err("Cannot remove '%s': required by installed package '%s'", name, l_name);
                blocked = true; 
                break;
            }
            tok = strtok(NULL, ",");
        }
        free(deps_copy);
        if (blocked) break;
    }
    sqlite3_finalize(stmt);
    if (blocked) return false;

    print_msg("Removing package %s...", name);
    if (sqlite3_prepare_v2(db, "SELECT filepath FROM files WHERE package = ? ORDER BY filepath DESC", -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT);
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *file = (const char*)sqlite3_column_text(stmt, 0);
            if (strncmp(file, "/etc/", 5) != 0) {
                if (unlink(file) == 0) {
                    char pcopy[PATH_MAX]; 
                    strncpy(pcopy, file, PATH_MAX-1);
                    char *dir = dirname(pcopy);
                    while (dir && strcmp(dir, "/") != 0 && strcmp(dir, ".") != 0) {
                        if (rmdir(dir) != 0) break;
                        strncpy(pcopy, dir, PATH_MAX-1); 
                        dir = dirname(pcopy);
                    }
                }
            }
        }
        sqlite3_finalize(stmt);
    }

    sqlite3_exec(db, "BEGIN EXCLUSIVE TRANSACTION;", 0, 0, 0);
    
    sqlite3_prepare_v2(db, "DELETE FROM files WHERE package = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT); 
    sqlite3_step(stmt); 
    sqlite3_finalize(stmt);

    sqlite3_prepare_v2(db, "DELETE FROM local_packages WHERE name = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_TRANSIENT); 
    sqlite3_step(stmt); 
    sqlite3_finalize(stmt);
    
    sqlite3_exec(db, "COMMIT;", 0, 0, 0);
    print_msg("Package %s removed cleanly.", name);
    return true;
}

void db_search(const char *query) {
    const char *sql = "SELECT name, version FROM sync.packages WHERE name LIKE ?";
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        print_err("Search failed. Did you run 'bhpkg -S' to sync the repository?");
        return;
    }

    char like_query[256];
    snprintf(like_query, sizeof(like_query), "%%%s%%", query);
    sqlite3_bind_text(stmt, 1, like_query, -1, SQLITE_TRANSIENT);

    printf("\n%s==> Search results for '%s':%s\n", C_BLD, query, C_RST);
    int found = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *p_name = (const char*)sqlite3_column_text(stmt, 0);
        const char *p_ver  = (const char*)sqlite3_column_text(stmt, 1);
        printf("  %s%s%s %s\n", C_CYN, p_name, C_RST, p_ver);
        found++;
    }
    
    if (found == 0) {
        printf("  No packages found matching that query.\n");
    }
    printf("\n");
    sqlite3_finalize(stmt);
}

void db_list_installed(void) {
    sqlite3_stmt *stmt;
    if (sqlite3_prepare_v2(db, "SELECT name, version FROM local_packages ORDER BY name", -1, &stmt, NULL) != SQLITE_OK) {
        print_err("Failed to query installed packages.");
        return;
    }

    printf("\n%s==> Installed Packages:%s\n", C_BLD, C_RST);
    int count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *p_name = (const char*)sqlite3_column_text(stmt, 0);
        const char *p_ver  = (const char*)sqlite3_column_text(stmt, 1);
        printf("  %s%s%s %s\n", C_GRN, p_name, C_RST, p_ver);
        count++;
    }
    printf("\n  Total: %d packages.\n", count);
    sqlite3_finalize(stmt);
}

void db_get_updates(BuildList *updates) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT l.name, l.version, s.version FROM local_packages l JOIN sync.packages s ON l.name = s.name";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) return;

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char*)sqlite3_column_text(stmt, 0);
        const char *local_ver = (const char*)sqlite3_column_text(stmt, 1);
        const char *remote_ver = (const char*)sqlite3_column_text(stmt, 2);
        
        if (strcmp(local_ver, remote_ver) != 0) {
            Package *pkg = db_fetch_manifest(name);
            if (pkg) {
                pkg->install_reason = 0;
                build_list_add(updates, pkg);
            }
        }
    }
    sqlite3_finalize(stmt);
}

bool db_check_conflict(const char *filepath, const char *pkg_name, char *owner_out) {
    sqlite3_stmt *stmt;
    bool conflict = false;
    const char *sql = "SELECT package FROM files WHERE filepath = ? AND package != ?";
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, filepath, -1, SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, pkg_name, -1, SQLITE_TRANSIENT);
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *owner = (const char*)sqlite3_column_text(stmt, 0);
            if (owner_out && owner) {
                strncpy(owner_out, owner, 255);
            }
            conflict = true;
        }
        sqlite3_finalize(stmt);
    }
    return conflict;
}

void db_close(void) {
    for (size_t i = 0; i < pkg_cache.count; i++) {
        Package *p = pkg_cache.pkgs[i];
        free(p->name); free(p->version); free(p->source_url); free(p->sha256); 
        free(p->build_script); free(p->pre_install); free(p->post_install);
        if (p->dep_names) {
            for (size_t j = 0; j < p->dep_count; j++) { 
                free(p->dep_names[j]); 
                free(p->dep_constraints[j]); 
            }
            free(p->dep_names); 
            free(p->dep_constraints);
        }
        free(p->deps); 
        free(p);
    }
    build_list_free(&pkg_cache);
    if (db) sqlite3_close(db);
}