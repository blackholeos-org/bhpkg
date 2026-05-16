#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/xattr.h>
#include <linux/capability.h>
#include <errno.h>
#include <sched.h>
#include <pwd.h>
#include <fnmatch.h>
#include <ftw.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <stddef.h>
#include "bhpkg.h"

char g_fakeroot[PATH_MAX];
char g_builddir[PATH_MAX];

static char **g_backup_files = NULL;
static char **g_target_files = NULL;
static size_t g_txn_count = 0;
static size_t g_txn_cap = 0;
static Package *g_current_pkg = NULL;
static bool g_txn_failed = false;

#define CHK_SYS(x) \
  do \
    { \
      if ((x) < 0) \
        { \
          fprintf (stderr, "Sandbox Err: %s failed (errno: %d)\n", #x, errno); \
          exit (127); \
        } \
    } \
  while (0)

static void
write_metadata_file (Package *pkg, const char *fakeroot)
{
  char path[PATH_MAX];
  snprintf (path, sizeof (path), "%s/.PKGINFO", fakeroot);
  FILE *f = fopen (path, "w");
  if (!f) return;

  fprintf (f, "name = \"%s\"\n", pkg->name);
  fprintf (f, "version = \"%s\"\n", pkg->version);
  fprintf (f, "architecture = \"%s\"\n", pkg->architecture);
  if (pkg->pre_install) fprintf (f, "pre_install = \"%s\"\n", pkg->pre_install);
  if (pkg->post_install) fprintf (f, "post_install = \"%s\"\n", pkg->post_install);
  fclose (f);
}

void
run_hook_script (const char *script_body, const char *hook_name)
{
  char path[] = "/var/lib/bhpkg/tmp/hook_XXXXXX";
  int fd;
  char *const args[] = { "/bin/sh", path, NULL };

  if (!script_body || strlen (script_body) == 0)
    return;

  fd = mkstemp (path);
  if (fd < 0)
    return;

  fchmod (fd, 0700);
  dprintf (fd, "#!/bin/sh\n%s\n", script_body);
  close (fd);

  if (g_verbosity > 0)
    print_msg ("Executing %s script...", hook_name);

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
          mkdir (tmp, 0755);
          *p = '/';
        }
    }
}

static void
apply_seccomp_whitelist (void)
{
  struct sock_filter filter[] = {
    BPF_STMT (BPF_LD | BPF_W | BPF_ABS, (offsetof (struct seccomp_data, arch))),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    BPF_STMT (BPF_LD | BPF_W | BPF_ABS, (offsetof (struct seccomp_data, nr))),

    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_ptrace, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_bpf, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_mount, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_init_module, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_finit_module, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_kexec_load, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP (BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, 0, 1),
    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),

    BPF_STMT (BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };

  struct sock_fprog prog = {
    .len = (unsigned short) (sizeof (filter) / sizeof (filter[0])),
    .filter = filter
  };

  CHK_SYS (prctl (PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  if (prctl (PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) < 0)
    {
      fprintf (stderr, "Sandbox Warning: Seccomp BPF filter failed. Sandboxing degraded.\n");
    }
}

static void
enter_hermetic_sandbox (const char *builddir, const char *fakeroot, bool net_access)
{
  int unshare_flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWUSER;
  if (!net_access)
    unshare_flags |= CLONE_NEWNET;

  if (unshare (unshare_flags) < 0)
    {
      unshare_flags &= ~CLONE_NEWUSER;
      CHK_SYS (unshare (unshare_flags));
    }

  if (unshare_flags & CLONE_NEWUSER)
    {
      int fd;
      char map_str[] = "0 0 4294967295\n";
      
      if ((fd = open ("/proc/self/uid_map", O_WRONLY)) >= 0)
        {
          if (write (fd, map_str, strlen (map_str)) < 0)
            fprintf (stderr, "Sandbox Warn: uid_map write failed (errno: %d)\n", errno);
          close (fd);
        }
      if ((fd = open ("/proc/self/setgroups", O_WRONLY)) >= 0)
        {
          if (write (fd, "deny\n", 5) < 0)
            fprintf (stderr, "Sandbox Warn: setgroups write failed (errno: %d)\n", errno);
          close (fd);
        }
      if ((fd = open ("/proc/self/gid_map", O_WRONLY)) >= 0)
        {
          if (write (fd, map_str, strlen (map_str)) < 0)
            fprintf (stderr, "Sandbox Warn: gid_map write failed (errno: %d)\n", errno);
          close (fd);
        }
    }

  pid_t child_pid = fork ();
  CHK_SYS (child_pid);

  if (child_pid > 0)
    {
      int wstatus;
      waitpid (child_pid, &wstatus, 0);
      exit (WIFEXITED (wstatus) ? WEXITSTATUS (wstatus) : 127);
    }

  CHK_SYS (mount ("none", "/", NULL, MS_REC | MS_PRIVATE, NULL));
  if (mkdir ("/tmp/sandbox", 0755) < 0 && errno != EEXIST)
    {
      fprintf (stderr, "Sandbox Err: mkdir (\"/tmp/sandbox\", 0755) failed (errno: %d)\n", errno);
      exit (127);
    }
  CHK_SYS (mount ("none", "/tmp/sandbox", "tmpfs", 0, "size=2G"));

  mkdir ("/tmp/sandbox/bin", 0755);
  mkdir ("/tmp/sandbox/sbin", 0755);
  mkdir ("/tmp/sandbox/usr", 0755);
  mkdir ("/tmp/sandbox/lib", 0755);
  mkdir ("/tmp/sandbox/etc", 0755);

  if (net_access)
    {
      mkdir ("/tmp/sandbox/etc/ssl", 0755);
      if (access ("/etc/ssl", F_OK) == 0)
        {
          CHK_SYS (mount ("/etc/ssl", "/tmp/sandbox/etc/ssl", NULL, MS_BIND | MS_REC, NULL));
          CHK_SYS (mount ("none", "/tmp/sandbox/etc/ssl", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
        }
      FILE *f = fopen ("/tmp/sandbox/etc/resolv.conf", "w");
      if (f)
        {
          fprintf (f, "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
          fclose (f);
        }
    }

  mkdir ("/tmp/sandbox/dev", 0755);
  mkdir ("/tmp/sandbox/proc", 0755);
  mkdir ("/tmp/sandbox/sys", 0755);
  mkdir ("/tmp/sandbox/build", 0777);
  mkdir ("/tmp/sandbox/dest", 0777);
  mkdir ("/tmp/sandbox/tmp_host", 0755);
  mkdir ("/tmp/sandbox/tmp", 0777);
  mkdir ("/tmp/sandbox/old_root", 0755);

  if (access ("/bin", F_OK) == 0)
    {
      CHK_SYS (mount ("/bin", "/tmp/sandbox/bin", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/bin", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/sbin", F_OK) == 0)
    {
      CHK_SYS (mount ("/sbin", "/tmp/sandbox/sbin", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/sbin", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/usr", F_OK) == 0)
    {
      CHK_SYS (mount ("/usr", "/tmp/sandbox/usr", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/usr", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/lib", F_OK) == 0)
    {
      CHK_SYS (mount ("/lib", "/tmp/sandbox/lib", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/lib", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/dev", F_OK) == 0)
    {
      CHK_SYS (mount ("/dev", "/tmp/sandbox/dev", NULL, MS_BIND | MS_REC, NULL));
    }

  if (access ("/libexec", F_OK) == 0)
    {
      mkdir ("/tmp/sandbox/libexec", 0755);
      CHK_SYS (mount ("/libexec", "/tmp/sandbox/libexec", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/libexec", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/x86_64-linux-musl", F_OK) == 0)
    {
      mkdir ("/tmp/sandbox/x86_64-linux-musl", 0755);
      CHK_SYS (mount ("/x86_64-linux-musl", "/tmp/sandbox/x86_64-linux-musl", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/x86_64-linux-musl", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  if (access ("/var/lib/bhpkg/tmp", F_OK) == 0)
    {
      CHK_SYS (mount ("/var/lib/bhpkg/tmp", "/tmp/sandbox/tmp_host", NULL, MS_BIND | MS_REC, NULL));
      CHK_SYS (mount ("none", "/tmp/sandbox/tmp_host", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL));
    }

  CHK_SYS (mount ("none", "/tmp/sandbox/tmp", "tmpfs", 0, "size=1G"));
  CHK_SYS (mount (builddir, "/tmp/sandbox/build", NULL, MS_BIND | MS_REC, NULL));
  CHK_SYS (mount (fakeroot, "/tmp/sandbox/dest", NULL, MS_BIND | MS_REC, NULL));

  CHK_SYS (mount ("proc", "/tmp/sandbox/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL));
  CHK_SYS (mount ("sysfs", "/tmp/sandbox/sys", "sysfs", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL));

  CHK_SYS (mount ("/tmp/sandbox", "/tmp/sandbox", NULL, MS_BIND | MS_REC, NULL));

  CHK_SYS (chdir ("/tmp/sandbox"));
  CHK_SYS (syscall (SYS_pivot_root, ".", "old_root"));

  umount2 ("/old_root", MNT_DETACH);
  CHK_SYS (chdir ("/"));

  umask (0022);

  CHK_SYS (setgroups (0, NULL));
  CHK_SYS (setregid (65534, 65534));
  CHK_SYS (setreuid (65534, 65534));

  apply_seccomp_whitelist ();
}

static Package *g_split_pkg;
static const char *g_split_fakeroot;

static int
subpackage_ftw_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  (void) sb;
  (void) ftwbuf;

  if (typeflag != FTW_F && typeflag != FTW_SL)
    return 0;

  const char *rel_path = fpath + strlen (g_split_fakeroot);
  if (*rel_path == '/')
    rel_path++;

  for (size_t i = 0; i < g_split_pkg->subpkg_count; i++)
    {
      SubpackageRule *rule = &g_split_pkg->subpackages[i];
      for (size_t p = 0; p < rule->pattern_count; p++)
        {
          if (fnmatch (rule->patterns[p], rel_path, FNM_PATHNAME) == 0)
            {
              char target[PATH_MAX];
              snprintf (target, sizeof (target), "%s-%s/%s", g_split_fakeroot, rule->name, rel_path);

              char tmp[PATH_MAX];
              snprintf (tmp, sizeof (tmp), "%s", target);
              for (char *c = tmp + 1; *c; c++)
                {
                  if (*c == '/')
                    {
                      *c = '\0';
                      mkdir (tmp, 0755);
                      *c = '/';
                    }
                }
              rename (fpath, target);
              return 0;
            }
        }
    }
  return 0;
}

void
split_subpackages_dynamic (Package *pkg, const char *fakeroot)
{
  g_split_pkg = pkg;
  g_split_fakeroot = fakeroot;

  for (size_t i = 0; i < pkg->subpkg_count; i++)
    {
      char sub_root[PATH_MAX];
      snprintf (sub_root, sizeof (sub_root), "%s-%s", fakeroot, pkg->subpackages[i].name);
      mkdir (sub_root, 0755);
    }

  nftw (fakeroot, subpackage_ftw_cb, 20, FTW_PHYS);

  for (size_t i = 0; i < pkg->subpkg_count; i++)
    {
      char sub_root[PATH_MAX], arc[PATH_MAX];
      snprintf (sub_root, sizeof (sub_root), "%s-%s", fakeroot, pkg->subpackages[i].name);
      snprintf (arc, sizeof (arc), "/var/cache/bhpkg/%s-%s-%s.tar.zst", pkg->name, pkg->subpackages[i].name, pkg->version);

      struct stat st;
      if (stat (sub_root, &st) == 0 && st.st_nlink > 2)
        {
          write_metadata_file (pkg, sub_root);
          archive_compress (sub_root, arc);
          if (g_verbosity > 0)
            print_msg ("Created dynamic subpackage %s-%s", pkg->name, pkg->subpackages[i].name);
        }
    }
}

bool
build_package (Package *pkg)
{
  char arc[PATH_MAX], scr[PATH_MAX];
  int fd_scr, status;
  pid_t pid;

  snprintf (g_builddir, sizeof (g_builddir), "/var/lib/bhpkg/tmp/build-%s-XXXXXX", pkg->name);
  snprintf (g_fakeroot, sizeof (g_fakeroot), "/var/lib/bhpkg/tmp/pkg-%s-XXXXXX", pkg->name);

  if (!mkdtemp (g_builddir) || !mkdtemp (g_fakeroot))
    return false;

  char **c_clean = xmalloc ((5 + pkg->subpkg_count) * sizeof (char *));
  c_clean[0] = "rm"; c_clean[1] = "-rf"; c_clean[2] = g_builddir; c_clean[3] = g_fakeroot;

  for (size_t i = 0; i < pkg->subpkg_count; i++)
    {
      char *sub_rm = xmalloc (PATH_MAX);
      snprintf (sub_rm, PATH_MAX, "%s-%s", g_fakeroot, pkg->subpackages[i].name);
      c_clean[4 + i] = sub_rm;
    }
  c_clean[4 + pkg->subpkg_count] = NULL;

  snprintf (arc, sizeof (arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);

  for (size_t i = 0; i < pkg->num_sources; i++)
    {
      char host_src[PATH_MAX], staged[PATH_MAX];
      snprintf (host_src, sizeof (host_src), "/var/lib/bhpkg/tmp/%s-%s-%zu.src", pkg->name, pkg->version, i);
      snprintf (staged, sizeof (staged), "%s/%s-%s-%zu.src", g_builddir, pkg->name, pkg->version, i);

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

  if (!safe_exec (c_chmod1) || !safe_exec (c_chmod2) || !safe_exec (c_chown1) || !safe_exec (c_chown2))
    {
      safe_exec (c_clean);
      return false;
    }

  snprintf (scr, sizeof (scr), "%s/bh-build.sh", g_builddir);
  fd_scr = open (scr, O_CREAT | O_WRONLY | O_TRUNC, 0755);
  if (fd_scr < 0) return false;

  fchmod (fd_scr, 0755);
  fchown (fd_scr, 65534, 65534);

  dprintf (fd_scr,
    "#!/bin/sh\n"
    "export PATH=\"/bin:/usr/bin:/sbin:/usr/sbin\"\n"
    "export DESTDIR=\"/dest\"\n"
    "export PREFIX=\"/usr\"\n"
    "export PKG_CONFIG_PATH=\"/usr/lib/pkgconfig:/usr/share/pkgconfig\"\n"
    "export PKG_CONFIG_LIBDIR=\"/usr/lib/pkgconfig:/usr/share/pkgconfig\"\n"
  );

  bool is_libc = (strcmp (pkg->name, "musl") == 0 || strcmp (pkg->name, "glibc") == 0);

  dprintf (fd_scr,
    "export CFLAGS=\"-O2 -pipe -fstack-protector-strong%s\"\n"
    "export CXXFLAGS=\"$CFLAGS\"\n"
    "export CPPFLAGS=\"%s\"\n"
    "export MAKEFLAGS=\"-j$(nproc 2>/dev/null || echo 4)\"\n"
    "if [ -d /usr/include/ncursesw ]; then\n"
    "  export CFLAGS=\"$CFLAGS -I/usr/include/ncursesw\"\n"
    "  export CXXFLAGS=\"$CXXFLAGS -I/usr/include/ncursesw\"\n"
    "  export CPPFLAGS=\"$CPPFLAGS -I/usr/include/ncursesw\"\n"
    "fi\n",
    is_libc ? "" : " -D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64",
    is_libc ? "" : "-D_GNU_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64"
  );

  for (size_t i = 0; i < g_use_flag_count; i++)
    {
      char flag_clean[64];
      strncpy (flag_clean, g_use_flags[i][0] == '-' ? g_use_flags[i] + 1 : g_use_flags[i], 63);
      for (char *c = flag_clean; *c; c++) *c = toupper (*c);
      dprintf (fd_scr, "export USE_%s=%d\n", flag_clean, g_use_flags[i][0] == '-' ? 0 : 1);
    }

  dprintf (fd_scr,
    "cd \"/build\" || exit 1\n"
    "cat << 'BH_EOF' | while read -r line; do echo \"+ $line\"; done\n"
    "%s\n"
    "BH_EOF\n"
    "%s\n", pkg->build_script, pkg->build_script);
  close (fd_scr);

  pid = fork ();
  if (pid == 0)
    {
      if (g_verbosity < 2)
        {
          mkdir ("/var/log", 0755);
          int log_fd = open ("/var/log/bhpkg-build.log", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
          if (log_fd >= 0)
            {
              fchown (log_fd, 65534, 65534);
              dup2 (log_fd, STDOUT_FILENO);
              dup2 (log_fd, STDERR_FILENO);
              close (log_fd);
            }
        }

      enter_hermetic_sandbox (g_builddir, g_fakeroot, pkg->net_access);

      for (size_t i = 0; i < pkg->num_sources; i++)
        {
          char src[PATH_MAX];
          snprintf (src, sizeof (src), "/build/%s-%s-%zu.src", pkg->name, pkg->version, i);
          if (strstr (pkg->sources[i], ".tar") || strstr (pkg->sources[i], ".tgz") || strstr (pkg->sources[i], ".txz"))
            {
              if (!archive_extract (src, strcmp (pkg->type, "binary") == 0 ? "/dest" : "/build", 1))
                {
                  fprintf (stderr, "Sandbox Err: archive_extract failed for %s\n", src);
                  exit (1);
                }
            }
        }

      if (strcmp (pkg->type, "binary") != 0)
        {
          execl ("/bin/sh", "sh", "/build/bh-build.sh", NULL);
          fprintf (stderr, "Sandbox Err: execl failed (errno: %d)\n", errno);
          exit (127);
        }
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
      if (g_verbosity == 1) printf ("\r\033[K\033[?25h");
    }
  else
    {
      while (waitpid (pid, &status, 0) == -1 && errno == EINTR);
    }

  if (!WIFEXITED (status) || WEXITSTATUS (status) != 0 || g_interrupted)
    {
      if (g_verbosity < 2) print_err ("Build script failed. Check /var/log/bhpkg-build.log for details.");
      else print_err ("Build script failed. Check the compilation output above for details.");
      safe_exec (c_clean);
      return false;
    }

  split_subpackages_dynamic (pkg, g_fakeroot);
  write_metadata_file (pkg, g_fakeroot);

  if (!archive_compress (g_fakeroot, arc))
    return false;

  safe_exec (c_clean);
  for (size_t i = 4; i < 4 + pkg->subpkg_count; i++) free (c_clean[i]);
  free (c_clean);

  pkg->is_cached = true;
  sync ();
  return true;
}

static int64_t
offin (uint8_t *buf)
{
  int64_t y = buf[7] & 0x7F;
  for (int i = 6; i >= 0; i--)
    {
      y = y * 256;
      y += buf[i];
    }
  if (buf[7] & 0x80) y = -y;
  return y;
}

bool
apply_binary_delta (const char *old_file, const char *delta_file, const char *new_file)
{
  int fd_old = open (old_file, O_RDONLY);
  int fd_patch = open (delta_file, O_RDONLY);
  int fd_new = open (new_file, O_CREAT | O_TRUNC | O_WRONLY, 0755);

  if (fd_old < 0 || fd_patch < 0 || fd_new < 0)
    {
      if (fd_old >= 0) close (fd_old);
      if (fd_patch >= 0) close (fd_patch);
      if (fd_new >= 0) close (fd_new);
      return false;
    }

  struct stat st;
  fstat (fd_old, &st);
  size_t old_size = st.st_size;
  uint8_t *old_data = xmalloc (old_size + 1);
  read (fd_old, old_data, old_size);
  close (fd_old);

  uint8_t header[32];
  if (read (fd_patch, header, 32) != 32 || memcmp (header, "BSDIFF40", 8) != 0)
    {
      print_err ("Invalid delta patch format.");
      free (old_data); close (fd_patch); close (fd_new);
      return false;
    }

  size_t ctrl_len = offin (header + 8);
  size_t diff_len = offin (header + 16);
  size_t new_size = offin (header + 24);

  uint8_t *new_data = xmalloc (new_size + 1);

  uint8_t *ctrl_buf = xmalloc (ctrl_len);
  uint8_t *diff_buf = xmalloc (diff_len);
  uint8_t *extra_buf = xmalloc (new_size);

  read (fd_patch, ctrl_buf, ctrl_len);
  read (fd_patch, diff_buf, diff_len);
  read (fd_patch, extra_buf, new_size);
  close (fd_patch);

  size_t old_pos = 0, new_pos = 0;
  size_t ctrl_pos = 0, diff_pos = 0, extra_pos = 0;

  while (new_pos < new_size)
    {
      int64_t ctrl[3];
      for (int i = 0; i < 3; i++)
        {
          ctrl[i] = offin (ctrl_buf + ctrl_pos);
          ctrl_pos += 8;
        }

      if (new_pos + ctrl[0] > new_size) break;

      for (int64_t i = 0; i < ctrl[0]; i++)
        {
          new_data[new_pos + i] = diff_buf[diff_pos++] +
                                  ((old_pos + i < old_size) ? old_data[old_pos + i] : 0);
        }
      new_pos += ctrl[0];
      old_pos += ctrl[0];

      if (new_pos + ctrl[1] > new_size) break;

      for (int64_t i = 0; i < ctrl[1]; i++)
        new_data[new_pos + i] = extra_buf[extra_pos++];

      new_pos += ctrl[1];
      old_pos += ctrl[2];
    }

  write (fd_new, new_data, new_size);
  close (fd_new);

  free (old_data);
  free (new_data);
  free (ctrl_buf);
  free (diff_buf);
  free (extra_buf);

  return true;
}

void
apply_delta_rm_manifest (const char *staging_dir)
{
  char manifest[PATH_MAX], line[PATH_MAX];
  snprintf (manifest, sizeof (manifest), "%s/.bhpkg-rm", staging_dir);

  FILE *f = fopen (manifest, "re");
  if (!f) return;

  while (fgets (line, sizeof (line), f))
    {
      line[strcspn (line, "\r\n")] = '\0';
      if (strlen (line) == 0) continue;

      char target[PATH_MAX * 2];
      snprintf (target, sizeof (target), "%s/%s", staging_dir, line);

      if (strstr (line, ".delta-patch"))
        {
          char orig_file[PATH_MAX * 2];
          snprintf (orig_file, sizeof (orig_file), "%s", target);
          orig_file[strlen (orig_file) - 12] = '\0';

          apply_binary_delta (orig_file, target, orig_file);
          unlink (target);
        }
      else
        {
          unlink (target);
          rmdir (target);
        }
    }
  fclose (f);
  unlink (manifest);
}

static void
track_txn_file (const char *target, const char *backup)
{
  if (g_txn_count >= g_txn_cap)
    {
      g_txn_cap = g_txn_cap == 0 ? 128 : g_txn_cap * 2;
      g_target_files = xrealloc (g_target_files, g_txn_cap * sizeof (char *));
      g_backup_files = xrealloc (g_backup_files, g_txn_cap * sizeof (char *));
    }
  g_target_files[g_txn_count] = xstrdup (target);
  g_backup_files[g_txn_count] = backup ? xstrdup (backup) : NULL;
  g_txn_count++;
}

void
rollback_filesystem (void)
{
  if (g_txn_count == 0) return;
  print_warn ("Transaction aborted. Rolling back filesystem state...");

  for (size_t i = g_txn_count; i > 0; i--)
    {
      const char *target = g_target_files[i - 1];
      const char *backup = g_backup_files[i - 1];

      if (backup)
        {
          unlink (target);
          rename (backup, target);
        }
      else
        {
          struct stat st;
          if (lstat (target, &st) == 0)
            {
              if (S_ISDIR (st.st_mode)) rmdir (target);
              else unlink (target);
            }
        }

      free (g_target_files[i - 1]);
      if (g_backup_files[i - 1]) free (g_backup_files[i - 1]);
    }

  free (g_target_files);
  free (g_backup_files);
  g_target_files = NULL;
  g_backup_files = NULL;
  g_txn_count = 0;
  g_txn_cap = 0;
}

bool
stage_artifact (Package *pkg)
{
  char arc[PATH_MAX];
  snprintf (arc, sizeof (arc), "/var/cache/bhpkg/%s-%s.tar.zst", pkg->name, pkg->version);
  snprintf (pkg->staging_dir, PATH_MAX, "/var/lib/bhpkg/tmp/staging-%s-XXXXXX", pkg->name);

  if (!mkdtemp (pkg->staging_dir)) return false;

  if (pkg->is_delta)
    {
      if (g_verbosity > 0) print_msg ("Applying binary Delta patch to staging layer...");
      db_reconstruct_to_staging (pkg->name, pkg->staging_dir);
    }

  if (!archive_extract (arc, pkg->staging_dir, 0)) return false;

  if (pkg->is_delta)
    apply_delta_rm_manifest (pkg->staging_dir);

  char pkginfo[PATH_MAX];
  snprintf (pkginfo, sizeof (pkginfo), "%s/.PKGINFO", pkg->staging_dir);
  if (access (pkginfo, F_OK) != 0)
    {
      print_err ("Artifact %s is missing .PKGINFO metadata. Refusing to install.", pkg->name);
      return false;
    }

  return true;
}

static void
apply_security_contexts (const char *fpath)
{
  (void) fpath;
}

static int
commit_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  char target[PATH_MAX];
  const char *rel_target = fpath + strlen (g_current_pkg->staging_dir);

  (void) ftwbuf;

  if (UNLIKELY (g_interrupted))
    {
      g_txn_failed = true;
      return -1;
    }

  if (*rel_target == '\0' || strcmp (rel_target, "/.PKGINFO") == 0) return 0;
  snprintf (target, sizeof (target), "%s", rel_target);

  if (typeflag == FTW_D)
    {
      ensure_parent_dir (target);
      if (mkdir (target, sb->st_mode) == 0) track_txn_file (target, NULL);
      return 0;
    }

  struct stat existing_st;
  char backup[PATH_MAX] = {0};

  if (lstat (target, &existing_st) == 0)
    {
      char db_hash[65] = {0}, owner[256] = {0};

      if (db_check_conflict (target, g_current_pkg->name, owner))
        {
          print_err ("Conflict! '%s' exists and is tracked by package '%s'.", target, owner);
          g_txn_failed = true;
          return -1;
        }

      if (strncmp (target, "/etc/", 5) == 0 && typeflag == FTW_F)
        {
          char cur_disk_hash[65] = {0}, staged_hash[65] = {0};
          crypto_hash_file (target, cur_disk_hash);
          crypto_hash_file (fpath, staged_hash);
          db_get_file_hash (target, db_hash);

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

      if (strcmp (target + strlen (target) - 10, ".bhpkg-new") != 0)
        {
          snprintf (backup, sizeof (backup), "%s.bhpkg-backup-XXXXXX", target);
          int fd = mkstemp (backup);
          if (fd >= 0)
            {
              close (fd);
              rename (target, backup);
              track_txn_file (target, backup);
            }
        }
      else
        track_txn_file (target, NULL);
    }
  else
    {
      ensure_parent_dir (target);
      track_txn_file (target, NULL);
    }

  if (typeflag == FTW_SL)
    {
      char link_target[PATH_MAX];
      ssize_t len = readlink (fpath, link_target, sizeof (link_target) - 1);
      if (len > 0)
        {
          link_target[len] = '\0';
          symlink (link_target, target);
        }
    }
  else
    {
      if (rename (fpath, target) != 0)
        {
          zero_copy_file (fpath, target, sb->st_mode);
          unlink (fpath);
        }
      apply_security_contexts (target);
    }

  return 0;
}

bool
commit_artifact (Package *pkg)
{
  g_current_pkg = pkg;
  g_txn_failed = false;
  run_hook_script (pkg->pre_install, "pre_install");

  db_register_package (pkg, pkg->staging_dir);

  if (nftw (pkg->staging_dir, commit_cb, 20, FTW_PHYS) != 0 || g_txn_failed)
    return false;

  run_hook_script (pkg->post_install, "post_install");

  return true;
}