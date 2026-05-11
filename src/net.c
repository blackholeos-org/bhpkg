#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "bhpkg.h"

struct XferInfo {
    char name[64];
    double dl_total;
    double dl_now;
};

static int progress_cb(void *p, curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow) {
    (void)ultotal; (void)ulnow;
    if (g_interrupted) return 1;
    struct XferInfo *info = (struct XferInfo *)p;
    info->dl_total = (double)dltotal;
    info->dl_now = (double)dlnow;
    return 0;
}

int net_download_all(BuildList *list) {
    if (list->count == 0) return 0;
    
    CURLM *multi = curl_multi_init();
    CURL **curls = xmalloc(list->count * sizeof(CURL *));
    FILE **files = xmalloc(list->count * sizeof(FILE *));
    struct XferInfo *infos = xmalloc(list->count * sizeof(struct XferInfo));

    print_msg("Fetching %zu packages from mirrors...", list->count);
    
    for (size_t i = 0; i < list->count; i++) {
        char fn[PATH_MAX];
        snprintf(fn, sizeof(fn), "/tmp/%s-%s.tar.gz", list->pkgs[i]->name, list->pkgs[i]->version);
        strncpy(infos[i].name, list->pkgs[i]->name, 63);
        infos[i].dl_total = 0; infos[i].dl_now = 0;

        files[i] = fopen(fn, "wb");
        curls[i] = curl_easy_init();
        curl_easy_setopt(curls[i], CURLOPT_URL, list->pkgs[i]->source_url);
        curl_easy_setopt(curls[i], CURLOPT_WRITEDATA, files[i]);
        curl_easy_setopt(curls[i], CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curls[i], CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(curls[i], CURLOPT_XFERINFOFUNCTION, progress_cb);
        curl_easy_setopt(curls[i], CURLOPT_XFERINFODATA, &infos[i]);
        curl_easy_setopt(curls[i], CURLOPT_NOPROGRESS, 0L);
        
        curl_easy_setopt(curls[i], CURLOPT_CAINFO, SSL_CERT_PATH); 
        curl_easy_setopt(curls[i], CURLOPT_TCP_FASTOPEN, 1L);
        curl_easy_setopt(curls[i], CURLOPT_TCP_KEEPALIVE, 1L);
        
        curl_multi_add_handle(multi, curls[i]);
    }

    int running = 1;
    while (running && !g_interrupted) {
        curl_multi_perform(multi, &running);
        curl_multi_poll(multi, NULL, 0, 100, NULL);
        
        for (size_t i = 0; i < list->count; i++) {
            double percent = infos[i].dl_total > 0 ? (infos[i].dl_now / infos[i].dl_total) * 100.0 : 0.0;
            printf("\r  %s%-15s%s | %3.0f%%[", C_BLD, infos[i].name, C_RST, percent);
            int filled = (int)(percent / 5.0);
            for(int j=0; j<20; j++) printf("%c", j < filled ? '#' : '-');
            printf("]");
            if (i < list->count - 1) printf("\n");
        }
        if (running) printf("\033[%zuA", list->count - 1);
    }
    printf("\n");

    for (size_t i = 0; i < list->count; i++) {
        curl_multi_remove_handle(multi, curls[i]);
        curl_easy_cleanup(curls[i]);
        fclose(files[i]);
        if (g_interrupted) {
            char fn[PATH_MAX];
            snprintf(fn, sizeof(fn), "/tmp/%s-%s.tar.gz", list->pkgs[i]->name, list->pkgs[i]->version);
            remove(fn); 
        }
    }
    curl_multi_cleanup(multi); free(curls); free(files); free(infos);
    return g_interrupted ? -1 : 0;
}