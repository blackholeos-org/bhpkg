#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <ftw.h>
#include <string.h>
#include <fcntl.h>
#include "bhpkg.h"

char g_fakeroot[PATH_MAX];
char g_builddir[PATH_MAX];
char g_staging[PATH_MAX];
static Package *g_current_pkg;
static bool g_install_failed;

static char **g_written_files = NULL;
static size_t g_written_count = 0;
static size_t g_written_capacity = 0;

static void
track_written_file (const char *path)
{
  if (g_written_count >= g_written_capacity)
    {
      g_written_capacity = g_written_capacity == 0 ? 128 : g_written_capacity * 2;
      g_written_files = xrealloc (g_written_files, g_written_capacity * sizeof (char *));
    }
  g_written_files[g_written_count++] = xstrdup (path);
}

static void
rollback_written_files (void)
{
  if (!g_written_files) return;
  print_warn ("Rolling back filesystem changes...");
  
  for (size_t i = g_written_count; i > 0; i--)
    {
      const char *path = g_written_files[i - 1];
      struct stat st;
      if (lstat (path, &st) == 0)
        {
          if (S_ISDIR (st.st_mode))
            rmdir (path);
          else
            unlink (path);
        }
      free (g_written_files[i - 1]);
    }
    
  free (g_written_files);
  g_written_files = NULL;
  g_written_count = 0;
  g_written_capacity = 0;
}

void
run_hook (const char *script_body, const char *hook_name)
{
  char path[] = "/var/lib/bhpkg/tmp/hook_XXXXXX";
  int fd;
  char *const args[] = { path, NULL };

  if (!script_body || strlen (script_body) == 0)
    return;

  fd = mkstemp (path);
  if (fd < 0)
    return;

  fchmod (fd, 0700);
  dprintf (fd, "#!/bin/sh\n%s\n", script_body);
  close (fd);

  safe_exec (args);
  unlink (path);
}

static void
ensure_parent_dir (const char *path)
{
  char tmp[PATH_MAX];
  char *p = NULL;

  snprintf (tmp, sizeof (tmp), "%s", path);
  for (p = tmp + 1; *p; p++)
    {
      if (*p == '/')
        {
          *p = '\0';
          if (mkdir (tmp, 0755) == 0)
            track_written_file (tmp);
          *p = '/';
        }
    }
}

static void
enter_hermetic_sandbox (const char *builddir, const char *fakeroot)
{
  if (unshare (CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET | CLONE_NEWPID) < 0)
    exit (127);

  pid_t child_pid = fork ();
  if (child_pid < 0) exit (127);
  if (child_pid > 0)
    {
      int wstatus;
      waitpid (child_pid, &wstatus, 0);
      exit (WIFEXITED (wstatus) ? WEXITSTATUS (wstatus) : 127);
    }

  mount ("none", "/", NULL, MS_REC | MS_PRIVATE, NULL);

  mkdir ("/tmp/sandbox", 0755);
  mount ("none", "/tmp/sandbox", "tmpfs", 0, "size=2G");

  mkdir ("/tmp/sandbox/bin", 0755);
  mkdir ("/tmp/sandbox/sbin", 0755);
  mkdir ("/tmp/sandbox/usr", 0755);
  mkdir ("/tmp/sandbox/lib", 0755);
  mkdir ("/tmp/sandbox/etc", 0755);
  mkdir ("/tmp/sandbox/dev", 0755);
  mkdir ("/tmp/sandbox/proc", 0755);
  mkdir ("/tmp/sandbox/sys", 0755);
  mkdir ("/tmp/sandbox/build", 0777);
  mkdir ("/tmp/sandbox/dest", 0777);
  mkdir ("/tmp/sandbox/tmp_host", 0755);
  mkdir ("/tmp/sandbox/tmp", 0777);
  mkdir ("/tmp/sandbox/old_root", 0755);

  mount ("/bin", "/tmp/sandbox/bin", NULL, MS_BIND | MS_REC, NULL);
  mount ("none", "/tmp/sandbox/bin", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);

  mount ("/sbin", "/tmp/sandbox/sbin", NULL, MS_BIND | MS_REC, NULL);
  mount ("none", "/tmp/sandbox/sbin", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);

  mount ("/usr", "/tmp/sandbox/usr", NULL, MS_BIND | MS_REC, NULL);
  mount ("none", "/tmp/sandbox/usr", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);

  mount ("/lib", "/tmp/sandbox/lib", NULL, MS_BIND | MS_REC, NULL);
  mount ("none", "/tmp/sandbox/lib", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
  mount ("/dev", "/tmp/sandbox/dev", NULL, MS_BIND | MS_REC, NULL);

  if (access ("/libexec", F_OK) == 0)
    {
      mkdir ("/tmp/sandbox/libexec", 0755);
      mount ("/libexec", "/tmp/sandbox/libexec", NULL, MS_BIND | MS_REC, NULL);
      mount ("none", "/tmp/sandbox/libexec", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
    }
  
  if (access ("/x86_64-linux-musl", F_OK) == 0)
    {
      mkdir ("/tmp/sandbox/x86_64-linux-musl", 0755);
      mount ("/x86_64-linux-musl", "/tmp/sandbox/x86_64-linux-musl", NULL, MS_BIND | MS_REC, NULL);
      mount ("none", "/tmp/sandbox/x86_64-linux-musl", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
    }

  mount ("/var/lib/bhpkg/tmp", "/tmp/sandbox/tmp_host", NULL, MS_BIND | MS_REC, NULL);
  mount ("none", "/tmp/sandbox/tmp_host", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);

  mount ("none", "/tmp/sandbox/tmp", "tmpfs", 0, "size=1G");
  mount (builddir, "/tmp/sandbox/build", NULL, MS_BIND | MS_REC, NULL);
  mount (fakeroot, "/tmp/sandbox/dest", NULL, MS_BIND | MS_REC, NULL);

  mount ("proc", "/tmp/sandbox/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);
  mount ("sysfs", "/tmp/sandbox/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL);

  mount ("/tmp/sandbox", "/tmp/sandbox", NULL, MS_BIND | MS_REC, NULL);

  if (chdir ("/tmp/sandbox") < 0) exit (127);
  if (syscall (SYS_pivot_root, ".", "old_root") < 0) exit (127);

  umount2 ("/old_root", MNT_DETACH);
  if (chdir ("/") < 0) exit (127);

  umask (0022);
  setgroups (0, NULL);
  if (setregid (65534, 65534) < 0 || setreuid (65534, 65534) < 0)
    exit (127);
}

bool
build_package (Package *pkg)
{
  char arc[PATH_MAX], scr[PATH_MAX];
  char *const c_clean[] = { "rm", "-rf", g_builddir, g_fakeroot, NULL };
  int fd_scr;
  pid_t pid;
  int status;

  snprintf (g_builddir, sizeof (g_builddir), "/var/lib/bhpkg/tmp/build-%s-XXXXXX", pkg->name);
  snprintf (g_fakeroot, sizeof (g_fakeroot), "/var/lib/bhpkg/tmp/pkg-%s-XXXXXX", pkg->name);
  snprintf (arc, sizeof (arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);

  if (!mkdtemp (g_builddir) || !mkdtemp (g_fakeroot))
    return false;

  for (size_t i = 0; i < pkg->num_sources; i++)
    {
      char host_src[PATH_MAX], staged[PATH_MAX];
      snprintf (host_src, sizeof (host_src), "/var/lib/bhpkg/tmp/%s-%s-%zu.src",
                pkg->name, pkg->version, i);
      snprintf (staged, sizeof (staged), "%s/%s-%s-%zu.src",
                g_builddir, pkg->name, pkg->version, i);
      if (!zero_copy_file (host_src, staged, 0644))
        {
          print_err ("Failed to stage source %zu for %s into builddir.", i, pkg->name);
          safe_exec (c_clean);
          return false;
        }
    }

  char *const c_chmod1[] = { "chmod", "-R", "0755", g_builddir, NULL };
  char *const c_chmod2[] = { "chmod", "-R", "0755", g_fakeroot, NULL };
  char *const c_chown1[] = { "chown", "-R", "65534:65534", g_builddir, NULL };
  char *const c_chown2[] = { "chown", "-R", "65534:65534", g_fakeroot, NULL };
  
  if (!safe_exec (c_chmod1) || !safe_exec (c_chmod2) || 
      !safe_exec (c_chown1) || !safe_exec (c_chown2))
    {
      print_err ("Failed to set build directory permissions.");
      safe_exec (c_clean);
      return false;
    }

  snprintf (scr, sizeof (scr), "%s/bh-build.sh", g_builddir);
  fd_scr = open (scr, O_CREAT | O_WRONLY | O_TRUNC, 0755);
  if (fd_scr < 0)
    return false;
  
  fchmod (fd_scr, 0755);
  fchown (fd_scr, 65534, 65534);
  
  dprintf (fd_scr,
    "#!/bin/sh\n"
    "export PATH=\"/bin:/usr/bin:/sbin:/usr/sbin\"\n"
    "export DESTDIR=\"/dest\"\n"
    "export PREFIX=\"/usr\"\n"
    "cd \"/build\" || exit 1\n"
    "printf '%%s\\n' \"%s\" | while read -r line; do echo \"+ $line\"; done\n"
    "%s\n",
    pkg->build_script, pkg->build_script);

  close (fd_scr);

  pid = fork ();
  if (pid == 0)
    {
      if (g_verbosity < 2)
        {
          int log_fd = open ("/var/log/bhpkg-build.log", O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
          if (log_fd >= 0)
            {
              fchown (log_fd, 65534, 65534);
              dup2 (log_fd, STDOUT_FILENO);
              dup2 (log_fd, STDERR_FILENO);
              close (log_fd);
            }
        }

      enter_hermetic_sandbox (g_builddir, g_fakeroot);

      for (size_t i = 0; i < pkg->num_sources; i++)
        {
          char src[PATH_MAX];
          snprintf (src, sizeof (src), "/build/%s-%s-%zu.src",
                    pkg->name, pkg->version, i);

          if (strstr (pkg->sources[i], ".tar") || strstr (pkg->sources[i], ".tgz")
              || strstr (pkg->sources[i], ".txz"))
            {
              if (!archive_extract (src,
                    strcmp (pkg->type, "binary") == 0 ? "/dest" : "/build", 1))
                exit (1);
            }
        }

      if (strcmp (pkg->type, "binary") != 0)
        execl ("/bin/sh", "sh", "/build/bh-build.sh", NULL);

      exit (0);
    }

  if (g_verbosity < 2)
    {
      if (g_verbosity == 1) printf ("\033[?25l");
      const char spin_chars[] = "-\\|/";
      int spin_idx = 0;

      while (waitpid (pid, &status, WNOHANG) == 0)
        {
          if (g_verbosity == 1)
            {
              printf ("\r  %s[%c]%s Compiling %s...\033[K", C_YLW, spin_chars[spin_idx], C_RST, pkg->name);
              fflush (stdout);
            }
          usleep (100000);
          spin_idx = (spin_idx + 1) % 4;
        }
        
      if (g_verbosity == 1)
        printf ("\r\033[K\033[?25h");
    }
  else
    {
      while (waitpid (pid, &status, 0) == -1 && errno == EINTR);
    }
  
  if (!WIFEXITED (status) || WEXITSTATUS (status) != 0 || g_interrupted)
    {
      print_err ("Build script failed. Check /var/log/bhpkg-build.log for details.");
      safe_exec (c_clean);
      return false;
    }

  if (!archive_compress (g_fakeroot, arc))
    return false;

  safe_exec (c_clean);
  pkg->is_cached = true;
  sync ();
  return true;
}

static int
install_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  const char *rel_target;
  char target[PATH_MAX];

  (void) ftwbuf;

  if (UNLIKELY (g_interrupted))
    {
      g_install_failed = true;
      return -1;
    }

  if (typeflag != FTW_F && typeflag != FTW_D && typeflag != FTW_SL)
    return 0;

  rel_target = fpath + strlen (g_staging);
  
  if (*rel_target == '\0' || strstr (rel_target, "/../") != NULL)
    return 0;

  snprintf (target, sizeof (target), "%s", rel_target);
  ensure_parent_dir (target);

  if (typeflag == FTW_D)
    {
      if (mkdir (target, sb->st_mode) == 0)
        track_written_file (target);
      return 0;
    }

  struct stat existing_st;
  if (lstat (target, &existing_st) == 0)
    {
      char db_hash[65] = { 0 };
      char owner[256] = { 0 };

      if (db_check_conflict (target, g_current_pkg->name, owner))
        {
          print_err ("Conflict! '%s' exists and is tracked by package '%s'.", target, owner);
          g_install_failed = true;
          return -1;
        }

      if (!db_get_file_hash (target, db_hash) && strncmp (target, "/etc/", 5) != 0)
        {
          if (S_ISLNK (existing_st.st_mode) ||
              strncmp (target, "/usr/", 5) == 0 || strncmp (target, "/bin/", 5) == 0 || 
              strncmp (target, "/lib/", 5) == 0 || strncmp (target, "/sbin/", 6) == 0 ||
              strncmp (target, "/libexec/", 9) == 0 || strncmp (target, "/include/", 9) == 0 ||
              strncmp (target, "/x86_64-linux-musl", 18) == 0)
            {
              if (g_verbosity >= 3)
                print_warn ("Adopting untracked file/symlink: %s", target);
            }
          else
            {
              print_err ("Conflict! '%s' exists but is untracked. Refusing to destroy user data.", target);
              g_install_failed = true;
              return -1;
            }
        }

      if (strncmp (target, "/etc/", 5) == 0 && typeflag == FTW_F)
        {
          char cur_disk_hash[65] = { 0 };
          char staged_hash[65] = { 0 };

          crypto_hash_file (target, cur_disk_hash);
          crypto_hash_file (fpath, staged_hash);

          if (db_hash[0] != '\0')
            {
              if (strcmp (cur_disk_hash, db_hash) != 0 && strcmp (cur_disk_hash, staged_hash) != 0)
                {
                  strncat (target, ".bhpkg-new", PATH_MAX - strlen (target) - 1);
                  print_warn ("Configuration modified. Installing new as %s", target);
                }
            }
          else
            {
              strncat (target, ".bhpkg-new", PATH_MAX - strlen (target) - 1);
              print_warn ("Untracked configuration exists. Installing new as %s", target);
            }
        }
    }

  if (typeflag == FTW_SL)
    {
      char link_target[PATH_MAX];
      ssize_t len = readlink (fpath, link_target, sizeof (link_target) - 1);
      if (len != -1)
        {
          link_target[len] = '\0';
          unlink (target);
          symlink (link_target, target);
          lchown (target, 0, 0);
          track_written_file (target);
        }
      return 0;
    }

  unlink (target);

  if (!zero_copy_file (fpath, target, sb->st_mode))
    {
      print_err ("Failed to copy extracted file to %s", target);
      g_install_failed = true;
      return -1;
    }
    
  if (chown (target, 0, 0) != 0)
    {
      if (g_verbosity >= 3)
        print_warn ("Failed to chown %s to root:root (errno: %d)", target, errno);
    }
    
  track_written_file (target);
  return 0;
}

bool
install_artifact (Package *pkg)
{
  char arc[PATH_MAX];
  char *const c_clean[] = { "rm", "-rf", g_staging, NULL };

  snprintf (arc, sizeof (arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);
  snprintf (g_staging, sizeof (g_staging), "/var/lib/bhpkg/tmp/staging-%s-XXXXXX", pkg->name);
  
  g_current_pkg = pkg;
  g_install_failed = false;

  if (!mkdtemp (g_staging))
    return false;

  if (!archive_extract (arc, g_staging, 0))
    {
      print_err ("Failed to extract cached archive for installation.");
      safe_exec (c_clean);
      return false;
    }

  run_hook (pkg->pre_install, "pre_install");
  
  nftw (g_staging, install_cb, 20, FTW_PHYS);

  if (g_install_failed || g_interrupted)
    {
      rollback_written_files ();
      db_rollback ();
      safe_exec (c_clean);
      return false;
    }

  run_hook (pkg->post_install, "post_install");

  db_register_package (pkg, g_staging);
  
  if (g_written_files)
    {
      for (size_t i = 0; i < g_written_count; i++) free (g_written_files[i]);
      free (g_written_files);
      g_written_files = NULL;
      g_written_count = 0;
      g_written_capacity = 0;
    }

  safe_exec (c_clean);
  sync ();
  return true;
}