#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include "bhpkg.h"

#ifndef SSL_CERT_PATH
#define SSL_CERT_PATH "/etc/ssl/certs/ca-certificates.crt"
#endif

struct XferInfo
{
  char name[128];
  double dl_total;
  double dl_now;
  char dest_path[PATH_MAX];
  char **mirrors;
  size_t mirror_count;
  size_t current_mirror;
  const char *expected_hash;
};

static void
parse_pipe_list (const char *str, char ***arr_out, size_t *count_out)
{
  char *copy, *tok;
  size_t count = 0;

  if (!str || !*str)
    {
      *count_out = 0;
      *arr_out = NULL;
      return;
    }
    
  copy = xstrdup (str);
  for (char *c = copy; *c; c++)
    if (*c == '|') count++;
    
  count++;
  
  *arr_out = xmalloc (count * sizeof (char *));
  tok = strtok (copy, "|");
  count = 0;
  
  while (tok)
    {
      while (*tok == ' ' || *tok == '\t') tok++;
      char *end = tok + strlen (tok) - 1;
      while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';
      
      (*arr_out)[count++] = xstrdup (tok);
      tok = strtok (NULL, "|");
    }
    
  *count_out = count;
  free (copy);
}

static int
progress_cb (void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
{
  struct XferInfo *info;

  (void) ultotal;
  (void) ulnow;

  if (UNLIKELY (g_interrupted))
    return 1;

  info = (struct XferInfo *) p;
  info->dl_total = (double) dltotal;
  info->dl_now = (double) dlnow;
  return 0;
}

int
net_download_all (BuildList *list)
{
  CURLM *multi;
  CURL **curls;
  FILE **files;
  struct XferInfo *infos;
  int running = 1;
  size_t total_downloads = 0;
  size_t idx = 0;
  bool download_failed = false;
  int last_percent = -1;
  int bar_width = 30;

  if (list->count == 0)
    return 0;

  for (size_t i = 0; i < list->count; i++)
    total_downloads += list->pkgs[i]->num_sources;

  if (total_downloads == 0)
    return 0;

  multi = curl_multi_init ();
  curl_multi_setopt (multi, CURLMOPT_PIPELINING, CURLPIPE_MULTIPLEX);

  curls = xmalloc (total_downloads * sizeof (CURL *));
  files = xmalloc (total_downloads * sizeof (FILE *));
  infos = xmalloc (total_downloads * sizeof (struct XferInfo));

  for (size_t i = 0; i < list->count; i++)
    {
      for (size_t j = 0; j < list->pkgs[i]->num_sources; j++)
        {
          char fn[PATH_MAX];
          snprintf (fn, sizeof (fn), "/var/lib/bhpkg/tmp/%s-%s-%zu.src", list->pkgs[i]->name, list->pkgs[i]->version, j);
          
          snprintf (infos[idx].name, sizeof (infos[idx].name), "%s", list->pkgs[i]->name);
          snprintf (infos[idx].dest_path, sizeof (infos[idx].dest_path), "%s", fn);
          infos[idx].dl_total = 0;
          infos[idx].dl_now = 0;          
          infos[idx].expected_hash = list->pkgs[i]->hashes ? list->pkgs[i]->hashes[j] : NULL;

          parse_pipe_list (list->pkgs[i]->sources[j], &infos[idx].mirrors, &infos[idx].mirror_count);
          infos[idx].current_mirror = 0;

          files[idx] = fopen (fn, "wbe");
          if (files[idx])
            fchmod (fileno (files[idx]), 0644);

          curls[idx] = curl_easy_init ();
          curl_easy_setopt (curls[idx], CURLOPT_URL, infos[idx].mirrors[0]);
          curl_easy_setopt (curls[idx], CURLOPT_WRITEDATA, files[idx]);
          curl_easy_setopt (curls[idx], CURLOPT_FOLLOWLOCATION, 1L);
          curl_easy_setopt (curls[idx], CURLOPT_MAXREDIRS, 10L);
          curl_easy_setopt (curls[idx], CURLOPT_FAILONERROR, 1L);
          curl_easy_setopt (curls[idx], CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
          curl_easy_setopt (curls[idx], CURLOPT_USERAGENT, "bhpkg/1.0 (Blackhole OS)");
          curl_easy_setopt (curls[idx], CURLOPT_XFERINFOFUNCTION, progress_cb);
          curl_easy_setopt (curls[idx], CURLOPT_XFERINFODATA, &infos[idx]);
          curl_easy_setopt (curls[idx], CURLOPT_NOPROGRESS, 0L);
          curl_easy_setopt (curls[idx], CURLOPT_CAINFO, SSL_CERT_PATH);
          curl_easy_setopt (curls[idx], CURLOPT_TCP_FASTOPEN, 1L);
          curl_easy_setopt (curls[idx], CURLOPT_TCP_KEEPALIVE, 1L);
          curl_easy_setopt (curls[idx], CURLOPT_BUFFERSIZE, 102400L);

          curl_multi_add_handle (multi, curls[idx]);
          idx++;
        }
    }

  if (g_verbosity >= 1)
    printf ("\033[?25l"); 

  while (running && !g_interrupted)
    {
      curl_multi_perform (multi, &running);
      curl_multi_poll (multi, NULL, 0, 100, NULL);

      double total_now = 0, total_expected = 0;
      for (size_t i = 0; i < total_downloads; i++)
        {
          total_now += infos[i].dl_now;
          if (infos[i].dl_total > 0)
            total_expected += infos[i].dl_total;
          else
            total_expected += infos[i].dl_now + 1;
        }

      double percent = (total_expected > 0) ? (total_now / total_expected) * 100.0 : 0.0;
      if (percent > 100.0) percent = 100.0;
      
      int current_percent = (int) percent;
      
      if (g_verbosity >= 1 && current_percent != last_percent)
        {
          int pos = (current_percent * bar_width) / 100;
          
          printf ("\r%s==>%s Fetching %zu sources... [", C_CYN, C_RST, total_downloads);
          if (g_pacman_mode)
            {
              for (int j = 0; j < bar_width; j++)
                {
                  if (j < pos) printf ("-");
                  else if (j == pos) printf ("%c", (current_percent % 2 == 0) ? 'C' : 'c');
                  else if (j % 2 == 0) printf ("o");
                  else printf (" ");
                }
            }
          else
            {
              for (int j = 0; j < bar_width; j++)
                {
                  if (j < pos) printf ("#");
                  else printf ("-");
                }
            }
          printf ("] %3.0f%%\033[K", percent);
          fflush (stdout);
          last_percent = current_percent;
        }
        
      int msgs_left;
      CURLMsg *msg;
      bool handle_retried = false;

      while ((msg = curl_multi_info_read (multi, &msgs_left))) 
        {
          if (msg->msg == CURLMSG_DONE) 
            {
              size_t i;
              for (i = 0; i < total_downloads; i++) 
                if (curls[i] == msg->easy_handle) break;

              bool success = (msg->data.result == CURLE_OK);

              if (success)
                {
                  if (files[i])
                    {
                      fclose (files[i]);
                      files[i] = NULL;
                    }

                  bool hash_ok = false;
                  
                  if (infos[i].expected_hash && infos[i].expected_hash[0] != '\0')
                    {
                      char *hash_copy = xstrdup (infos[i].expected_hash);
                      char *tok = strtok (hash_copy, "|");
                      while (tok)
                        {
                          while (*tok == ' ' || *tok == '\t') tok++;
                          char *end = tok + strlen (tok) - 1;
                          while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';

                          if (crypto_verify_sha256 (infos[i].dest_path, tok))
                            {
                              hash_ok = true;
                              break;
                            }
                          tok = strtok (NULL, "|");
                        }
                      free (hash_copy);
                    }
                  else
                    {
                      hash_ok = true; /* Skip verification for dynamic files without hashes */
                    }

                  if (!hash_ok)
                    {
                      if (g_verbosity >= 1) printf ("\r\033[K");
                      print_warn ("Hash mismatch for '%s' on %s. Suspected mirror desync.", 
                                  infos[i].name, infos[i].mirrors[infos[i].current_mirror]);
                      success = false; /* Force failover */
                    }
                }

              if (!success)
                {
                  if (infos[i].current_mirror + 1 < infos[i].mirror_count)
                    {
                      infos[i].current_mirror++;
                      if (g_verbosity >= 1) printf ("\r\033[K");
                      print_warn ("Falling back to: %s", infos[i].mirrors[infos[i].current_mirror]);
                      
                      curl_multi_remove_handle (multi, curls[i]);
                      if (files[i]) fclose (files[i]);
                      
                      files[i] = fopen (infos[i].dest_path, "wbe");
                      if (files[i]) fchmod (fileno (files[i]), 0644);
                      
                      curl_easy_setopt (curls[i], CURLOPT_URL, infos[i].mirrors[infos[i].current_mirror]);
                      curl_easy_setopt (curls[i], CURLOPT_WRITEDATA, files[i]);
                      curl_multi_add_handle (multi, curls[i]);
                      handle_retried = true;
                    }
                  else
                    {
                      if (g_verbosity >= 1) printf ("\r\033[K");
                      print_err ("All mirrors exhausted or failed integrity checks for '%s'.", infos[i].name);
                      if (msg->data.result != CURLE_OK)
                        print_err ("cURL Error: %s", curl_easy_strerror (msg->data.result));
                      download_failed = true;
                    }
                }
              else
                {
                   if (g_verbosity >= 1 && infos[i].expected_hash)
                     printf ("\r\033[K  %s[PASS]%s %s\n", C_GRN, C_RST, infos[i].name);
                }
            }
        }
      if (handle_retried) running = 1;
    }
    
  if (g_verbosity >= 1)
    {
      printf ("\r%s==>%s Fetching %zu sources... [", C_CYN, C_RST, total_downloads);
      for (int j = 0; j < bar_width; j++) printf (g_pacman_mode ? "-" : "#");
      printf ("] 100%%\033[K\n\033[?25h"); 
    }

  idx = 0;
  for (size_t i = 0; i < list->count; i++)
    {
      for (size_t j = 0; j < list->pkgs[i]->num_sources; j++)
        {
          curl_multi_remove_handle (multi, curls[idx]);
          curl_easy_cleanup (curls[idx]);
          if (files[idx])
            fclose (files[idx]);
          
          if (g_interrupted || download_failed)
            remove (infos[idx].dest_path);

          if (infos[idx].mirrors)
            {
              for (size_t k = 0; k < infos[idx].mirror_count; k++) free (infos[idx].mirrors[k]);
              free (infos[idx].mirrors);
            }
          idx++;
        }
    }

  curl_multi_cleanup (multi);
  free (curls);
  free (files);
  free (infos);

  return (g_interrupted || download_failed) ? -1 : 0;
}