#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include "bhpkg.h"

volatile sig_atomic_t g_interrupted = 0;

void handle_signal(int sig) { 
    (void)sig; 
    g_interrupted = 1; 
    print_err("Interrupt caught. Safely halting operations..."); 
}

void print_help() {
    printf("\n%sBlackhole Package Manager (bhpkg)%s\n", C_BLD, C_RST);
    printf("  -S, --sync          Sync repository database\n");
    printf("  -i, --install <pkg> Install a package\n");
    printf("  -u, --update        Update entire system\n");
    printf("  -u  <pkg>           Update a specific package\n");
    printf("  -R, --remove  <pkg> Remove a package\n");
    printf("  -Ss <query>         Search online repository\n");
    printf("  -Q                  List installed packages\n");
    printf("  -Sc                 Clean cache directory\n\n");
}

void cache_prune(void) {
    print_msg("Cleaning cache directory (/var/cache/bhpkg)...");
    DIR *dir = opendir("/var/cache/bhpkg");
    if (!dir) { 
        print_err("Failed to open cache directory."); 
        return; 
    }
    
    struct dirent *ent;
    int count = 0;
    while ((ent = readdir(dir)) != NULL) {
        if (ent->d_type == DT_REG) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/var/cache/bhpkg/%s", ent->d_name);
            if (unlink(path) == 0) {
                count++;
            }
        }
    }
    closedir(dir);
    print_msg("Removed %d cached artifacts.", count);
}

void process_build_queue(BuildList *order) {
    BuildList to_download; 
    build_list_init(&to_download);

    for (size_t i = 0; i < order->count; i++) {
        Package *p = order->pkgs[i];
        char cache_path[256]; 
        snprintf(cache_path, sizeof(cache_path), "/var/cache/bhpkg/%s-%s.tar.zst", p->name, p->version);
        
        if (access(cache_path, F_OK) == 0) {
            p->is_cached = true;
        }
        if (!p->is_installed && !p->is_cached) {
            build_list_add(&to_download, p);
        }
    }

    if (to_download.count > 0) {
        if (net_download_all(&to_download) != 0 || g_interrupted) {
            goto build_cleanup;
        }
        
        print_msg("Verifying SHA256 cryptographic hashes...");
        for (size_t i = 0; i < to_download.count; i++) {
            char fn[256]; 
            snprintf(fn, sizeof(fn), "/tmp/%s-%s.tar.gz", to_download.pkgs[i]->name, to_download.pkgs[i]->version);
            
            if (!crypto_verify_sha256(fn, to_download.pkgs[i]->sha256)) {
                print_err("Integrity check failed for %s! Potential MITM attack.", to_download.pkgs[i]->name); 
                exit(1);
            }
            printf("  %s[PASS]%s %s\n", C_GRN, C_RST, to_download.pkgs[i]->name);
        }
    }

    for (size_t i = 0; i < order->count; i++) {
        if (g_interrupted) break;
        Package *p = order->pkgs[i];
        
        if (p->is_installed) {
            printf("  %s[SKIP]%s %s is already up to date.\n", C_GRN, C_RST, p->name);
            continue;
        }

        print_msg("Processing [%s%s%s]", C_YLW, p->name, C_RST);
        
        if (!p->is_cached && !build_package(p)) { 
            print_err("Build failed for %s.", p->name); 
            exit(1); 
        }
        
        Package *old_p = db_fetch_manifest(p->name);
        if (old_p && old_p->is_installed) {
            print_warn("Upgrading existing package: %s", p->name);
        }
        
        if (!install_artifact(p)) { 
            print_err("Install failed for %s.", p->name); 
            exit(1); 
        }
    }

build_cleanup:
    build_list_free(&to_download);
}

int main(int argc, char **argv) {
    if (argc < 2) { 
        print_help(); 
        return 0; 
    }

    if (geteuid() != 0) { 
        print_err("bhpkg must be run as root to modify the system."); 
        return 1; 
    }

    signal(SIGINT, handle_signal); 
    signal(SIGTERM, handle_signal);
    mkdir("/var/lib/bhpkg", 0755); 
    mkdir("/var/cache/bhpkg", 0755); 
    mkdir("/etc/bhpkg", 0755);

    db_init();

    if (strcmp(argv[1], "-Ss") == 0 && argc == 3) { 
        db_search(argv[2]); 
    } 
    else if (strcmp(argv[1], "-Q") == 0) { 
        db_list_installed(); 
    } 
    else if (strcmp(argv[1], "-Sc") == 0) { 
        cache_prune(); 
    } 
    else if (strcmp(argv[1], "-S") == 0) { 
        db_sync_repo(); 
    } 
    else if (strcmp(argv[1], "-R") == 0 && argc == 3) { 
        db_remove_package(argv[2]); 
    }
    else if (strcmp(argv[1], "-u") == 0) {
        if (!db_sync_repo()) {
            print_err("Failed to sync repo, aborting update.");
            db_close();
            return 1;
        }
        
        BuildList up; 
        build_list_init(&up); 
        
        if (argc == 3) {
            Package *pkg = db_fetch_manifest(argv[2]);
            if (!pkg) { 
                print_err("Package '%s' not found.", argv[2]); 
                db_close();
                return 1; 
            }
            if (!pkg->is_installed) { 
                print_err("Package '%s' is not installed locally.", argv[2]); 
                db_close();
                return 1; 
            }
            pkg->install_reason = 0;
            build_list_add(&up, pkg);
        } else {
            db_get_updates(&up);
        }
        
        if (up.count == 0) { 
            print_msg("System is fully up-to-date."); 
        } else {
            print_msg("System upgrade triggered. Processing %zu packages...", up.count);
            for (size_t i = 0; i < up.count; i++) {
                if (g_interrupted) break;
                BuildList order; 
                build_list_init(&order);
                resolve_dependencies(up.pkgs[i], &order); 
                process_build_queue(&order); 
                build_list_free(&order);
            }
        }
        build_list_free(&up);
    }
    else if (strcmp(argv[1], "-i") == 0 && argc == 3) {
        Package *pkg = db_fetch_manifest(argv[2]);
        if (!pkg) { 
            print_err("Package '%s' not found in sync.db!", argv[2]); 
            db_close();
            return 1; 
        }
        
        pkg->install_reason = 0;
        
        BuildList order; 
        build_list_init(&order);
        resolve_dependencies(pkg, &order);
        process_build_queue(&order);
        build_list_free(&order);
    }
    else { 
        print_help(); 
    }
    
    db_close(); 
    return 0;
}