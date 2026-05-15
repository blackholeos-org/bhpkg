#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include "bhpkg.h"

int g_verbosity = 1;
bool g_pacman_mode = false;

void *
xmalloc (size_t size)
{
  void *ptr = malloc (size);
  if (UNLIKELY (!ptr && size != 0))
    {
      print_err ("Out of memory! Recovering and rolling back database state.");
      db_rollback ();
      exit (EXIT_FAILURE);
    }
  return ptr;
}

void *
xrealloc (void *ptr, size_t size)
{
  void *new_ptr = realloc (ptr, size);
  if (UNLIKELY (!new_ptr && size != 0))
    {
      print_err ("Out of memory during reallocation! Rolling back.");
      db_rollback ();
      exit (EXIT_FAILURE);
    }
  return new_ptr;
}

char *
xstrdup (const char *s)
{
  if (!s) return NULL;
  char *dup = strdup (s);
  if (UNLIKELY (!dup))
    {
      print_err ("Out of memory allocating string duplicate! Rolling back.");
      db_rollback ();
      exit (EXIT_FAILURE);
    }
  return dup;
}

void
print_msg (const char *msg, ...)
{
  if (g_verbosity < 1)
    return;
    
  va_list args;
  printf ("%s==>%s %s", C_CYN, C_RST, C_BLD);
  va_start (args, msg);
  vprintf (msg, args);
  va_end (args);
  printf ("%s\n", C_RST);
}

void
print_err (const char *msg, ...)
{
  va_list args;
  fprintf (stderr, "%s==> ERROR:%s %s", C_RED, C_RST, C_BLD);
  va_start (args, msg);
  vfprintf (stderr, msg, args);
  va_end (args);
  fprintf (stderr, "%s\n", C_RST);
}

void
print_warn (const char *msg, ...)
{
  va_list args;
  printf ("%s==> WARNING:%s %s", C_YLW, C_RST, C_BLD);
  va_start (args, msg);
  vprintf (msg, args);
  va_end (args);
  printf ("%s\n", C_RST);
}

bool
safe_exec (char *const argv[])
{
  pid_t pid = fork ();
  int status;

  if (pid < 0)
    return false;
  if (pid == 0)
    {
      execvp (argv[0], argv);
      exit (127);
    }
    
  waitpid (pid, &status, 0);
  return WIFEXITED (status) && WEXITSTATUS (status) == 0;
}

bool
zero_copy_file (const char *src, const char *dst, mode_t mode)
{
  int fd_in;
  int fd_out;
  struct stat sb;
  size_t len;
  ssize_t ret;

  fd_in = open (src, O_RDONLY | O_CLOEXEC | O_NOATIME);
  if (fd_in < 0 && errno == EPERM)
    fd_in = open (src, O_RDONLY | O_CLOEXEC);

  fd_out = open (dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  
  if (fd_in < 0 || fd_out < 0)
    {
      if (fd_in >= 0) close (fd_in);
      if (fd_out >= 0) close (fd_out);
      return false;
    }

  fchmod (fd_out, mode);

  if (fstat (fd_in, &sb) != 0)
    {
      close (fd_in);
      close (fd_out);
      return false;
    }
  
  len = sb.st_size;

#if defined(POSIX_FADV_SEQUENTIAL)
  posix_fadvise (fd_in, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

  while (len > 0)
    {
      ret = copy_file_range (fd_in, NULL, fd_out, NULL, len, 0);
      if (ret < 0)
        {
          char buf[32768];
          ssize_t bytes_read = read (fd_in, buf, sizeof (buf));
          if (bytes_read <= 0)
            break;
          if (write (fd_out, buf, bytes_read) < 0)
            break;
          len -= bytes_read;
        }
      else if (ret == 0)
        {
          break;
        }
      else
        {
          len -= ret;
        }
    }
    
  fsync (fd_out);
  
  close (fd_in);
  close (fd_out);
  return true;
}

void
package_free (Package *p)
{
  if (!p) return;
  
  if (p->name) free (p->name);
  if (p->version) free (p->version);
  if (p->type) free (p->type);
  if (p->license) free (p->license);
  if (p->build_script) free (p->build_script);
  if (p->pre_install) free (p->pre_install);
  if (p->post_install) free (p->post_install);
  if (p->pre_remove) free (p->pre_remove);
  if (p->post_remove) free (p->post_remove);
  
  if (p->sources)
    {
      for (size_t j = 0; j < p->num_sources; j++)
        if (p->sources[j]) free (p->sources[j]);
      free (p->sources);
    }
    
  if (p->hashes)
    {
      for (size_t j = 0; j < p->num_sources; j++)
        if (p->hashes[j]) free (p->hashes[j]);
      free (p->hashes);
    }
    
  if (p->dep_names)
    {
      for (size_t j = 0; j < p->dep_count; j++)
        {
          if (p->dep_names[j]) free (p->dep_names[j]);
          if (p->dep_constraints[j]) free (p->dep_constraints[j]);
        }
      free (p->dep_names);
      free (p->dep_constraints);
    }
    
  if (p->makedep_names)
    {
      for (size_t j = 0; j < p->makedep_count; j++)
        {
          if (p->makedep_names[j]) free (p->makedep_names[j]);
          if (p->makedep_constraints[j]) free (p->makedep_constraints[j]);
        }
      free (p->makedep_names);
      free (p->makedep_constraints);
    }
    
  free (p);
}