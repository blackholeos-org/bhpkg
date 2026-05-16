#include <archive.h>
#include <archive_entry.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ftw.h>
#include <errno.h>
#include "bhpkg.h"

bool
archive_extract (const char *filename, const char *dest_dir, int strip_components)
{
  struct archive *a;
  struct archive *ext;
  struct archive_entry *entry;
  int flags;
  char cwd[PATH_MAX];
  bool success = true;
  int r_hdr;

  a = archive_read_new ();
  ext = archive_write_disk_new ();

  flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_SECURE_NODOTDOT
          | ARCHIVE_EXTRACT_SECURE_SYMLINKS | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;

  if (geteuid () == 0)
    flags |= ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS;

  archive_read_support_filter_all (a);
  archive_read_support_format_all (a);

  archive_read_set_filter_option (a, "zstd", "threads", "0");
  archive_clear_error (a);

  archive_write_disk_set_options (ext, flags);

  int fd = open (filename, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    {
      print_err ("archive_extract: manual open failed for %s (Errno: %d, %s)", filename, errno, strerror(errno));
      archive_read_free (a);
      archive_write_free (ext);
      return false;
    }

  if (archive_read_open_fd (a, fd, 65536) != ARCHIVE_OK)
    {
      print_err ("archive_extract: failed to read archive %s (%s)", filename, archive_error_string(a));
      close (fd);
      archive_read_free (a);
      archive_write_free (ext);
      return false;
    }

  if (getcwd (cwd, sizeof (cwd)) == NULL)
    {
      print_err ("archive_extract: getcwd failed (errno: %d)", errno);
      close (fd);
      archive_read_free (a);
      archive_write_free (ext);
      return false;
    }

  if (chdir (dest_dir) != 0)
    {
      print_err ("archive_extract: chdir to %s failed (errno: %d)", dest_dir, errno);
      close (fd);
      archive_read_free (a);
      archive_write_free (ext);
      return false;
    }

  while ((r_hdr = archive_read_next_header (a, &entry)) == ARCHIVE_OK || r_hdr == ARCHIVE_WARN)
    {
      const char *p = archive_entry_pathname (entry);
      
      if (strip_components > 0)
        {
          const char *stripped = p;
          int count = strip_components;
          while (count > 0 && stripped)
            {
              stripped = strchr (stripped, '/');
              if (stripped) stripped++;
              count--;
            }

          if (!stripped || *stripped == '\0')
            continue;
            
          archive_entry_set_pathname (entry, stripped);

          const char *hl = archive_entry_hardlink (entry);
          if (hl)
            {
              const char *hl_stripped = hl;
              int hl_count = strip_components;
              while (hl_count > 0 && hl_stripped)
                {
                  hl_stripped = strchr (hl_stripped, '/');
                  if (hl_stripped) hl_stripped++;
                  hl_count--;
                }
              if (hl_stripped && *hl_stripped != '\0')
                archive_entry_set_hardlink (entry, hl_stripped);
            }
        }

      int r = archive_write_header (ext, entry);
      if (r == ARCHIVE_OK || r == ARCHIVE_WARN)
        {
          const void *buff;
          size_t size;
          la_int64_t offset;
          int data_r;

          while ((data_r = archive_read_data_block (a, &buff, &size, &offset)) == ARCHIVE_OK || data_r == ARCHIVE_WARN)
            {
              archive_write_data_block (ext, buff, size, offset);
            }
        }
      archive_write_finish_entry (ext);
    }
    
  if (r_hdr != ARCHIVE_EOF && r_hdr != ARCHIVE_OK && r_hdr != ARCHIVE_WARN)
    {
       print_warn ("archive_extract: extraction terminated early with code %d", r_hdr);
       success = false;
    }

  if (chdir (cwd) != 0)
    {
      print_err ("archive_extract: chdir back to %s failed (errno: %d)", cwd, errno);
      success = false;
    }

  archive_read_close (a);
  archive_read_free (a);
  archive_write_close (ext);
  archive_write_free (ext);
  close (fd);
  
  return success;
}

static struct archive *g_arc_write = NULL;
static const char *g_arc_src_dir = NULL;

static int
compress_cb (const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
  struct archive_entry *entry;
  const char *rel_path;

  (void) ftwbuf;

  if (typeflag != FTW_F && typeflag != FTW_D && typeflag != FTW_SL)
    return 0;

  entry = archive_entry_new ();
  rel_path = fpath + strlen (g_arc_src_dir);
  
  if (*rel_path == '/')
    rel_path++;
    
  if (*rel_path == '\0')
    {
      archive_entry_free (entry);
      return 0;
    }

  archive_entry_set_pathname (entry, rel_path);
  archive_entry_copy_stat (entry, sb);

  if (typeflag == FTW_SL)
    {
      char link_target[PATH_MAX];
      ssize_t len = readlink (fpath, link_target, sizeof (link_target) - 1);
      if (len >= 0)
        {
          link_target[len] = '\0';
          archive_entry_set_symlink (entry, link_target);
        }
      archive_write_header (g_arc_write, entry);
    }
  else if (typeflag == FTW_F)
    {
      int fd;
      
      archive_write_header (g_arc_write, entry);
      fd = open (fpath, O_RDONLY | O_CLOEXEC | O_NOATIME);
      if (fd < 0 && errno == EPERM)
        fd = open (fpath, O_RDONLY | O_CLOEXEC);

      if (fd >= 0)
        {
#if defined(POSIX_FADV_SEQUENTIAL)
          posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
          char buff[32768];
          int len;
          while ((len = read (fd, buff, sizeof (buff))) > 0)
            archive_write_data (g_arc_write, buff, len);
          close (fd);
        }
    }
  else
    {
      archive_write_header (g_arc_write, entry);
    }
    
  archive_entry_free (entry);
  return 0;
}

bool
archive_compress (const char *src_dir, const char *dest_archive)
{
  g_arc_write = archive_write_new ();
  archive_write_add_filter_zstd (g_arc_write);
  archive_write_set_format_pax_restricted (g_arc_write);

  if (archive_write_open_filename (g_arc_write, dest_archive) != ARCHIVE_OK)
    {
      archive_write_free (g_arc_write);
      return false;
    }

  g_arc_src_dir = src_dir;
  nftw (src_dir, compress_cb, 20, FTW_PHYS);

  archive_write_close (g_arc_write);
  archive_write_free (g_arc_write);
  return true;
}