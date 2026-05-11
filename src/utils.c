#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "bhpkg.h"

void *xmalloc(size_t size) {
    void *ptr = malloc(size);
    if (!ptr && size != 0) { print_err("Out of memory!"); exit(1); }
    return ptr;
}

void *xrealloc(void *ptr, size_t size) {
    void *new_ptr = realloc(ptr, size);
    if (!new_ptr && size != 0) { print_err("Out of memory!"); exit(1); }
    return new_ptr;
}

char *xstrdup(const char *s) {
    char *dup = strdup(s);
    if (!dup) { print_err("Out of memory!"); exit(1); }
    return dup;
}

void print_msg(const char *msg, ...) {
    printf("%s==>%s %s", C_CYN, C_RST, C_BLD);
    va_list args; va_start(args, msg); vprintf(msg, args); va_end(args);
    printf("%s\n", C_RST);
}

void print_err(const char *msg, ...) {
    fprintf(stderr, "%s==> ERROR:%s %s", C_RED, C_RST, C_BLD);
    va_list args; va_start(args, msg); vfprintf(stderr, msg, args); va_end(args);
    fprintf(stderr, "%s\n", C_RST);
}

void print_warn(const char *msg, ...) {
    printf("%s==> WARNING:%s %s", C_YLW, C_RST, C_BLD);
    va_list args; va_start(args, msg); vprintf(msg, args); va_end(args);
    printf("%s\n", C_RST);
}

bool safe_exec(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return false;
    if (pid == 0) { execvp(argv[0], argv); exit(127); }
    int status; waitpid(pid, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

bool zero_copy_file(const char *src, const char *dst, mode_t mode) {
    int fd_in = open(src, O_RDONLY);
    int fd_out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd_in < 0 || fd_out < 0) {
        if (fd_in >= 0) close(fd_in);
        if (fd_out >= 0) close(fd_out);
        return false;
    }

    struct stat sb; fstat(fd_in, &sb);
    size_t len = sb.st_size; ssize_t ret;

    while (len > 0) {
        ret = copy_file_range(fd_in, NULL, fd_out, NULL, len, 0);
        if (ret < 0) { 
            char buf[32768];
            ssize_t bytes_read = read(fd_in, buf, sizeof(buf));
            if (bytes_read <= 0) break;
            write(fd_out, buf, bytes_read);
            len -= bytes_read;
        } else { len -= ret; }
    }
    close(fd_in); close(fd_out);
    return true;
}