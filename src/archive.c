#include <archive.h>
#include <archive_entry.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ftw.h>
#include "bhpkg.h"

bool archive_extract(const char *filename, const char *dest_dir) {
    struct archive *a = archive_read_new();
    struct archive *ext = archive_write_disk_new();
    struct archive_entry *entry;
    int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL 
              | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);
    archive_write_disk_set_options(ext, flags);

    if (archive_read_open_filename(a, filename, 16384) != ARCHIVE_OK) return false;

    char cwd[PATH_MAX]; getcwd(cwd, sizeof(cwd));
    chdir(dest_dir);

    bool success = true;
    while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
        const char *p = archive_entry_pathname(entry);
        const char *stripped = strchr(p, '/');
        if (stripped && *(stripped + 1) != '\0') {
            archive_entry_set_pathname(entry, stripped + 1);
            if (archive_write_header(ext, entry) == ARCHIVE_OK) {
                const void *buff; size_t size; la_int64_t offset;
                while (archive_read_data_block(a, &buff, &size, &offset) == ARCHIVE_OK) {
                    archive_write_data_block(ext, buff, size, offset);
                }
            }
            archive_write_finish_entry(ext);
        }
    }
    chdir(cwd);
    archive_read_close(a); archive_read_free(a);
    archive_write_close(ext); archive_write_free(ext);
    return success;
}

static struct archive *g_arc_write = NULL;
static const char *g_arc_src_dir = NULL;

static int compress_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)ftwbuf;
    if (typeflag != FTW_F && typeflag != FTW_D) return 0;

    struct archive_entry *entry = archive_entry_new();
    const char *rel_path = fpath + strlen(g_arc_src_dir);
    if (*rel_path == '/') rel_path++;
    if (*rel_path == '\0') { archive_entry_free(entry); return 0; }

    archive_entry_set_pathname(entry, rel_path);
    archive_entry_copy_stat(entry, sb);

    if (typeflag == FTW_F) {
        archive_write_header(g_arc_write, entry);
        int fd = open(fpath, O_RDONLY);
        if (fd >= 0) {
            char buff[32768]; int len;
            while ((len = read(fd, buff, sizeof(buff))) > 0) archive_write_data(g_arc_write, buff, len);
            close(fd);
        }
    } else {
        archive_write_header(g_arc_write, entry);
    }
    archive_entry_free(entry);
    return 0;
}

bool archive_compress(const char *src_dir, const char *dest_archive) {
    g_arc_write = archive_write_new();
    archive_write_add_filter_zstd(g_arc_write);
    archive_write_set_format_pax_restricted(g_arc_write);
    if (archive_write_open_filename(g_arc_write, dest_archive) != ARCHIVE_OK) return false;

    g_arc_src_dir = src_dir;
    nftw(src_dir, compress_cb, 20, FTW_PHYS);

    archive_write_close(g_arc_write);
    archive_write_free(g_arc_write);
    return true;
}