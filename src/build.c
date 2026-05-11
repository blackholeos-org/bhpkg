#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sched.h>
#include <pwd.h>
#include <ftw.h>
#include <string.h>
#include "bhpkg.h"

char g_fakeroot[PATH_MAX], g_builddir[PATH_MAX], g_staging[PATH_MAX];
static Package *g_current_pkg;
static bool g_install_failed;

void run_hook(const char *script_body, const char *hook_name) {
    if (!script_body || strlen(script_body) == 0) return;
    print_msg("Running %s hook...", hook_name);
    
    char path[PATH_MAX]; snprintf(path, sizeof(path), "/tmp/bhpkg_hook_%s.sh", hook_name);
    FILE *f = fopen(path, "w"); 
    if (!f) return;
    fprintf(f, "#!/bin/sh\n%s\n", script_body); 
    fclose(f);
    chmod(path, 0755);
    
    char *const args[] = {path, NULL}; 
    safe_exec(args);
    remove(path);
}

bool build_package(Package *pkg) {
    char src[PATH_MAX], arc[PATH_MAX], scr[PATH_MAX];
    snprintf(src, sizeof(src), "/tmp/%s-%s.tar.gz", pkg->name, pkg->version);
    snprintf(g_builddir, PATH_MAX, "/tmp/bhpkg-build-%s", pkg->name);
    snprintf(g_fakeroot, PATH_MAX, "/tmp/bhpkg-pkg-%s", pkg->name);
    snprintf(arc, sizeof(arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);
    snprintf(scr, sizeof(scr), "/tmp/bhpkg-script-%s.sh", pkg->name);

    print_msg("Isolating Build Environment for %s...", pkg->name);
    
    // Clean up any old environments
    char *const c_clean[] = {"rm", "-rf", g_builddir, g_fakeroot, NULL}; safe_exec(c_clean);
    mkdir(g_builddir, 0777); mkdir(g_fakeroot, 0777);
    
    if (!archive_extract(src, g_builddir)) {
        print_err("Failed to extract source archive."); return false;
    }

    FILE *script = fopen(scr, "w");
    fprintf(script, "#!/bin/sh\nset -e\nexport DESTDIR=\"%s\"\nexport PREFIX=\"/usr\"\ncd \"%s\"\n%s\n", 
            g_fakeroot, g_builddir, pkg->build_script);
    fclose(script); chmod(scr, 0755);

    pid_t pid = fork();
    if (pid == 0) {
        if (unshare(CLONE_NEWNET | CLONE_NEWNS) < 0) {
            //theoretically shouldnt happen
            print_err("Kernel does not support namespaces. Build continuing without isolation.");
        }
        
        setgroups(0, NULL);
        struct passwd *pw = getpwnam("nobody");
        if (pw) { 
            setregid(pw->pw_gid, pw->pw_gid); 
            setreuid(pw->pw_uid, pw->pw_uid); 
        } else {
            setregid(65534, 65534);
            setreuid(65534, 65534);
        }
        
        execl(scr, scr, NULL); 
        exit(127);
    }
    
    int status; waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0 || g_interrupted) {
        print_err("Build script failed with non-zero exit code.");
        return false;
    }

    print_msg("Compressing final artifact via ZSTD...");
    if (!archive_compress(g_fakeroot, arc)) return false;
    
    char *const c_finalize[] = {"rm", "-rf", g_builddir, g_fakeroot, scr, src, NULL}; safe_exec(c_finalize);
    pkg->is_cached = true;
    return true;
}

static int install_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (g_interrupted) { g_install_failed = true; return -1; }
    if (typeflag != FTW_F && typeflag != FTW_D && typeflag != FTW_SL) return 0;
    
    const char *rel_target = fpath + strlen(g_staging);
    if (*rel_target == '\0') return 0;

    char target[PATH_MAX];
    snprintf(target, sizeof(target), "%s", rel_target);

    if (typeflag == FTW_D) { mkdir(target, sb->st_mode); return 0; }
    
    if (strncmp(target, "/etc/", 5) == 0 && access(target, F_OK) == 0) {
        snprintf(target, sizeof(target), "%s.new", rel_target);
        print_warn("Configuration exists. Installing upstream config as: %s", target);
    }
    
    if (typeflag == FTW_SL) {
        char link_target[PATH_MAX];
        ssize_t len = readlink(fpath, link_target, sizeof(link_target) - 1);
        if (len != -1) {
            link_target[len] = '\0';
            unlink(target); 
            symlink(link_target, target);
        }
        return 0;
    }

    char owner[256];
    if (db_check_conflict(target, g_current_pkg->name, owner)) {
        print_err("File conflict! %s is owned by %s", target, owner);
        g_install_failed = true; return -1;
    }

    zero_copy_file(fpath, target, sb->st_mode); 
    return 0;
}

bool install_artifact(Package *pkg) {
    char arc[PATH_MAX]; snprintf(arc, sizeof(arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);
    snprintf(g_staging, PATH_MAX, "/tmp/bhpkg-staging-%s", pkg->name);
    g_current_pkg = pkg;
    g_install_failed = false;
    
    char *const c_clean[] = {"rm", "-rf", g_staging, NULL}; safe_exec(c_clean);
    mkdir(g_staging, 0755);
    
    if (!archive_extract(arc, g_staging)) {
        print_err("Failed to extract cached archive for installation.");
        return false;
    }

    run_hook(pkg->pre_install, "pre_install");
    print_msg("Installing %s mapped to root (/)...\n", pkg->name);    
    nftw(g_staging, install_cb, 20, FTW_PHYS);
    
    if (g_install_failed || g_interrupted) {
        db_rollback();
        safe_exec(c_clean);
        return false;
    }

    run_hook(pkg->post_install, "post_install");

    db_register_package(pkg, g_staging);
    safe_exec(c_clean);
    return true;
}