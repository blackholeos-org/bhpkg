#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <fnmatch.h>
#include "bhpkg.h"

static void
strip_whitespace (char *str)
{
  char *p = str;
  int l = strlen (p);
  while (l > 0 && (p[l - 1] == ' ' || p[l - 1] == '\n' || p[l - 1] == '\r')) p[--l] = '\0';
  while (*p == ' ' || *p == '\t') p++;
  if (p != str) memmove (str, p, l + 1);
}

static void
process_hook_file (const char *filepath, const char *target_op)
{
  FILE *f = fopen (filepath, "r");
  char line[256];
  bool matches_op = false;
  char desc[256] = {0};
  char exec_cmd[256] = {0};
  
  if (!f) return;

  while (fgets (line, sizeof (line), f))
    {
      strip_whitespace (line);
      if (line[0] == '#' || line[0] == '\0' || line[0] == '[') continue;

      char *key = strtok (line, "=");
      char *val = strtok (NULL, "=");
      if (!key || !val) continue;

      strip_whitespace (key);
      strip_whitespace (val);

      if (strcmp (key, "Operation") == 0 && strcmp (val, target_op) == 0)
        matches_op = true;
      else if (strcmp (key, "Description") == 0)
        strncpy (desc, val, sizeof (desc) - 1);
      else if (strcmp (key, "Exec") == 0)
        strncpy (exec_cmd, val, sizeof (exec_cmd) - 1);
    }
  fclose (f);

  if (matches_op && exec_cmd[0])
    {
      if (desc[0] && g_verbosity > 0) print_msg ("Hook: %s", desc);
      char *const args[] = { "/bin/sh", "-c", exec_cmd, NULL };
      safe_exec (args);
    }
}

void
hook_execute_all (const char *operation)
{
  DIR *d = opendir ("/etc/bhpkg/hooks");
  struct dirent *dir;

  if (!d) return;

  while ((dir = readdir (d)) != NULL)
    {
      if (strstr (dir->d_name, ".hook"))
        {
          char path[PATH_MAX];
          snprintf (path, sizeof (path), "/etc/bhpkg/hooks/%s", dir->d_name);
          process_hook_file (path, operation);
        }
    }
  closedir (d);
}

static void
evaluate_single_hook (const char *hook_path, const char *staging_dir)
{
  FILE *f = fopen (hook_path, "r");
  char line[512], target_pattern[256] = {0}, exec_cmd[256] = {0};

  if (!f) return;
  while (fgets (line, sizeof (line), f))
    {
      char *key = strtok (line, "=");
      char *val = strtok (NULL, "\n");
      if (!key || !val) continue;

      strip_whitespace (key);
      strip_whitespace (val);

      if (strcmp (key, "TriggerOn") == 0) strncpy (target_pattern, val, 255);
      else if (strcmp (key, "Exec") == 0) strncpy (exec_cmd, val, 255);
    }
  fclose (f);

  if (target_pattern[0] && exec_cmd[0])
    {
      char cmd[1024];
      snprintf (cmd, sizeof (cmd), "find %s -path '%s' | grep -q .", staging_dir, target_pattern);
      if (system (cmd) == 0)
        {
          print_msg ("Triggering hook: %s", hook_path);
          char *const args[] = { "/bin/sh", "-c", exec_cmd, NULL };
          safe_exec (args);
        }
    }
}

void
hook_evaluate_triggers (const char *staging_dir)
{
  DIR *d = opendir ("/etc/bhpkg/hooks");
  struct dirent *dir;

  if (!d) return;

  while ((dir = readdir (d)) != NULL)
    {
      if (strstr (dir->d_name, ".hook"))
        {
          char path[PATH_MAX];
          snprintf (path, sizeof (path), "/etc/bhpkg/hooks/%s", dir->d_name);
          evaluate_single_hook (path, staging_dir);
        }
    }
  closedir (d);
}