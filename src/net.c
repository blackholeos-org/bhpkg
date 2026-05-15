#define _GNU_SOURCE
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
};

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
          
          snprintf (infos[idx].name, sizeof (infos[idx].name), "%s (src %zu)", list->pkgs[i]->name, j + 1);
          infos[idx].dl_total = 0;
          infos[idx].dl_now = 0;

          files[idx] = fopen (fn, "wbe");
          if (files[idx])
            {
              fchmod (fileno (files[idx]), 0644);
            }

          curls[idx] = curl_easy_init ();
          curl_easy_setopt (curls[idx], CURLOPT_URL, list->pkgs[i]->sources[j]);
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
    printf ("\033[?25l"); /* Hide cursor */

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
                  if (j < pos)
                    printf ("-");
                  else if (j == pos)
                    printf ("%c", (current_percent % 2 == 0) ? 'C' : 'c');
                  else if (j % 2 == 0)
                    printf ("o");
                  else
                    printf (" ");
                }
            }
          else
            {
              for (int j = 0; j < bar_width; j++)
                {
                  if (j < pos)
                    printf ("#");
                  else
                    printf ("-");
                }
            }
            
          printf ("] %3.0f%%\033[K", percent);
          fflush (stdout);
          last_percent = current_percent;
        }
    }
    
  if (g_verbosity >= 1)
    {
      printf ("\r%s==>%s Fetching %zu sources... [", C_CYN, C_RST, total_downloads);
      for (int j = 0; j < bar_width; j++) printf (g_pacman_mode ? "-" : "#");
      printf ("] 100%%\033[K\n");
      printf ("\033[?25h"); /* Show cursor */
    }

  int msgs_left;
  CURLMsg *msg;
  while ((msg = curl_multi_info_read (multi, &msgs_left))) 
    {
      if (msg->msg == CURLMSG_DONE) 
        {
          if (msg->data.result != CURLE_OK) 
            {
              for (size_t i = 0; i < total_downloads; i++) 
                {
                  if (curls[i] == msg->easy_handle) 
                    {
                      print_err ("Network error downloading '%s': %s", 
                                 infos[i].name, curl_easy_strerror (msg->data.result));
                      break;
                    }
                }
              download_failed = true;
            }
        }
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
            {
              char fn[PATH_MAX];
              snprintf (fn, sizeof (fn), "/var/lib/bhpkg/tmp/%s-%s-%zu.src", list->pkgs[i]->name, list->pkgs[i]->version, j);
              remove (fn);
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