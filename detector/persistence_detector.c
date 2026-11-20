#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MIN_DETECTION_SCORE 10
#define MAX_FILE_SIZE (10U * 1024U * 1024U)
#define MAX_SCANNED_MODULES 256

static int risk_score = 0;
static char scanned_modules[MAX_SCANNED_MODULES][PATH_MAX];
static size_t scanned_modules_count = 0;

static const char *const sus_names[] = {
    "rootkit", "revshell", "reverse_shell", "hide_kld", "kld_hiding", "rklog", "keylog", "backdoor",
    "stealth", "keylogger", "/dev/rootkit", "magic_trigger", "hide_module", NULL
};

static const char *const known_sus_paths[] = {
    "/boot/modules/rootkit.ko",
    "/boot/modules/hiding.ko",
    "/usr/local/bin/revshell",
    "/usr/local/bin/rklog",
    "/etc/rootkit_remote_ip",
    "/dev/rootkit",
    NULL
};

static const char *const persistence_files[] = {
    "/etc/rc.local",
    "/etc/rc.conf",
    "/etc/rc.conf.local",
    "/etc/rc.d/kld",
    "/etc/conf.d/local.start",
    "/etc/crontab",
    "/etc/periodic.conf",
    "/etc/periodic.conf.local",
    "/etc/inetd.conf",
    "/etc/libmap.conf",
    "/boot/loader.conf",
    "/boot/loader.conf.local",
    "/boot/modules/rootkit.ko",
    "/boot/modules/hiding.ko",
    NULL
};

static const char *const persistence_directories[] = {
    "/etc/cron.d",
    "/usr/local/etc/cron.d",
    "/usr/local/etc/rc.d",
    "/etc/periodic",
    "/usr/local/etc/periodic",
    NULL
};
enum dir_type {
    DIR_CONFIG,
    DIR_MODULE
};

static void add_score(int points) {
    risk_score += points;
}

static int search_string_from_bytes(const void *data, size_t length, const char *text) {
    return memmem(data, length, text, strlen(text)) != NULL;
}

static int search_text_case_insensitive(const char *text, const char *string) {
    return strcasestr(text, string) != NULL;
}

static int is_sus_name(const char *name) {
    for (int i = 0; sus_names[i] != NULL; i++) {
        if (search_text_case_insensitive(name, sus_names[i])) {
            return 1;
        }
    }
    return 0;
}

static int is_module_scanned(const char *path) {
    for (size_t i = 0; i < scanned_modules_count; i++) {
        if (strcmp(scanned_modules[i], path) == 0) {
            return 1;
        }
    }

    if (scanned_modules_count < MAX_SCANNED_MODULES) {
        strncpy(scanned_modules[scanned_modules_count], path, PATH_MAX - 1);
        scanned_modules[scanned_modules_count][PATH_MAX - 1] = '\0';
        scanned_modules_count++;
    }
    return 0;
}

static void remove_comments(char *line) {
    char quote = '\0';
    int is_escaped = 0;
    char *curr;

    for (curr = line; *curr != '\0'; curr++) {
        if (is_escaped) {
            is_escaped = 0;
            continue;
        }

        if (*curr == '\\') {
            is_escaped = 1;
            continue;
        }

        if ((*curr == '\'' || *curr == '"')) {
            if (quote == '\0') {
                quote = *curr;
            } else if (quote == *curr) {
                quote = '\0';
            }
            continue;
        }

        if (*curr == '#' && quote == '\0') {
            *curr = '\0';
            return;
        }
    }
}

static void scan_known_sus_paths(void) {
    struct stat st;
    for (int i = 0; known_sus_paths[i] != NULL; i++) {
        if (lstat(known_sus_paths[i], &st) == 0) {
            add_score(MIN_DETECTION_SCORE);
        }
    }
}

static int read_file(const char *path, unsigned char **output, size_t *length) {
    struct stat st;
    unsigned char *data;
    size_t file_size;
    size_t total_bytes_read = 0;
    ssize_t bytes_read;

    *output = NULL;
    *length = 0;

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        return -1;
    }

    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 || (uintmax_t)st.st_size > MAX_FILE_SIZE) {
        close(fd);
        return -1;
    }

    file_size = (size_t)st.st_size;

    data = malloc(file_size + 1);
    if (data == NULL) {
        close(fd);
        return -1;
    }

    while (total_bytes_read < file_size) {
        bytes_read = read(fd, data + total_bytes_read,
            file_size - total_bytes_read);
        if (bytes_read <= 0) {
            close(fd);
            free(data);
            return -1;
        }
        total_bytes_read += bytes_read;
    }

    close(fd);
    data[total_bytes_read] = '\0';
    *output = data;
    *length = total_bytes_read;

    return 0;
}

static void scan_module_file(const char *path) {
    struct stat st;
    unsigned char *data;
    size_t len;

    if (is_module_scanned(path)) {
        return;
    }

    if (strcmp(path, "/boot/kernel/kernel") == 0 || strcmp(path, "/boot/kernel/kernel.old") == 0) {
        return;
    }

    if (lstat(path, &st) < 0) {
        return;
    }

    if (read_file(path, &data, &len) < 0) {
        return;
    }

    if (is_sus_name(path)) {
        add_score(1);
    }

    if (st.st_uid != 0 || st.st_mode & (S_IWGRP | S_IWOTH)) {
        add_score(1);
    }

    for (int i = 0; sus_names[i] != NULL; i++) {
        if (search_string_from_bytes(data, len, sus_names[i])) {
            add_score(MIN_DETECTION_SCORE);
            
            free(data);
            return;
        }
    }

    int has_dir_hook = search_string_from_bytes(data, len, "getdirentries");
    int has_creds = search_string_from_bytes(data, len, "cr_uid") ||
                    search_string_from_bytes(data, len, "crcopy") ||
                    search_string_from_bytes(data, len, "crget") ||
                    search_string_from_bytes(data, len, "crset");
    int has_device = search_string_from_bytes(data, len, "make_dev");
    int has_linker_refs = search_string_from_bytes(data, len, "linker_files") ||
                           search_string_from_bytes(data, len, "kld_sx");
    int has_sysent = search_string_from_bytes(data, len, "sysent");

    if (has_dir_hook && has_sysent && has_linker_refs) {
        add_score(MIN_DETECTION_SCORE);
    } else if (has_sysent && has_creds && has_device) {
        add_score(MIN_DETECTION_SCORE);
    }

    free(data);
}

static void scan_boot_module(const char *name) {
    int len;
    char path[PATH_MAX];
    size_t name_len = strlen(name);
    const char *suffix = name_len >= 3 &&
        strcmp(name + name_len - 3, ".ko") == 0 ? "" : ".ko";


    if (name_len == 0 || name_len >= PATH_MAX) {
        return;
    }

    if (is_sus_name(name)) {
        add_score(MIN_DETECTION_SCORE);
    }

    if (name[0] == '/') {
        scan_module_file(name);
        return;
    }

    len = snprintf(path, sizeof(path), "/boot/modules/%s%s", name, suffix);

    if (len < 0 || len >= (int)sizeof(path)) {
        return;
    }

    if (access(path, F_OK) == 0) {
        scan_module_file(path);
        return;
    }

    len = snprintf(path, sizeof(path), "/boot/kernel/%s%s", name, suffix);

    if (len >= 0 && len < (int)sizeof(path)) {
        scan_module_file(path);
    }
}

static void scan_module_configs(char *line) {
    char module[PATH_MAX];
    char *curr;
    char *value;
    char *start;
    char *load_pos;
    char *saveptr = NULL;
    char *mod_name;

    if (search_text_case_insensitive(line, "kld_list")) {
        curr = strchr(line, '=');
        if (curr == NULL) {
            return;
        }

        value = curr + 1;

        for (curr = value; *curr != '\0'; curr++) {
            if (*curr == '\t' || *curr == ',' || *curr == '\'' || *curr == '"') {
                *curr = ' ';
            }
        }

        mod_name = strtok_r(value, " \r\n", &saveptr);
        while (mod_name != NULL) {
            scan_boot_module(mod_name);
            mod_name = strtok_r(NULL, " \r\n", &saveptr);
        }
        return;
    }

    load_pos = strstr(line, "_load");
    if (load_pos == NULL || !search_text_case_insensitive(load_pos, "yes")) {
        return;
    }

    start = line;
    while(isspace((unsigned char)*start)) {
        start++;
    }

    size_t len = (size_t)(load_pos - start);
    if (len == 0 || len >= sizeof(module)) {
        return;
    }

    memcpy(module, start, len);
    module[len] = '\0';

    scan_boot_module(module);
}

static void scan_active_config(const char *path) {
    char *content;
    ssize_t len;
    char *line = NULL;
    size_t cap = 0;

    FILE *file = fopen(path, "r");
    if (file == NULL) {
        return;
    }

    while ((len = getline(&line, &cap, file)) != -1) {
        remove_comments(line);

        content = line;
        while (isspace((unsigned char)*content)) {
            content++;
        }

        if (*content == '\0') {
            continue;
        }

        for (int i = 0; sus_names[i] != NULL; i++) {
            if (search_text_case_insensitive(content, sus_names[i])) {
                add_score(MIN_DETECTION_SCORE);
                break;
            }
        }

        if (search_text_case_insensitive(content, "kld_load") &&
            (search_text_case_insensitive(content, "/root/") ||
            search_text_case_insensitive(content, "/tmp") ||
            search_text_case_insensitive(content, "/var/tmp") ||
            search_text_case_insensitive(content, "/home/"))
        ) {
            add_score(MIN_DETECTION_SCORE);
        }

        if (search_text_case_insensitive(line, "/dev/tcp/") ||
            (search_text_case_insensitive(line, "socat") &&
            (search_text_case_insensitive(line, "exec:") ||
            search_text_case_insensitive(line, "system:"))) ||
            (search_text_case_insensitive(line, "nc ") &&
            (search_text_case_insensitive(line, " -e ") ||
            search_text_case_insensitive(line, " -c ")))
        ) {
            add_score(MIN_DETECTION_SCORE);
        }


        scan_module_configs(content);
    }
    free(line);
    fclose(file);
}

static void scan_directory(const char *directory, enum dir_type type, int depth) {
    struct stat st;
    struct dirent *dir_entry;
    char path[PATH_MAX];
    int path_length;

    if (depth < 0) {
        return;
    }

    DIR *dir = opendir(directory);
    if (dir == NULL) {
        return;
    }

    while ((dir_entry = readdir(dir)) != NULL) {
        if (strcmp(dir_entry->d_name, ".") == 0 || strcmp(dir_entry->d_name, "..") == 0) {
            continue;
        }

        path_length = snprintf(path, sizeof(path), "%s/%s", directory,
            dir_entry->d_name);
        if (path_length < 0 || (size_t)path_length >= sizeof(path)) {
            continue;
        }

        if (lstat(path, &st) < 0) {
            continue;
        }

        if (S_ISDIR(st.st_mode) && type == DIR_CONFIG) {
            scan_directory(path, type, depth - 1);
            continue;
        }

        size_t len = strlen(dir_entry->d_name);

        if (!S_ISREG(st.st_mode))
            continue;

        if (type == DIR_CONFIG) {
            scan_active_config(path);
        } else if (type == DIR_MODULE &&
                len >= 3 &&
                strcmp(dir_entry->d_name + len - 3, ".ko") == 0) {
            scan_module_file(path);
        }
    }
    closedir(dir);
}

static int
persistence_detector_run(void)
{
    risk_score = 0;
    scanned_modules_count = 0;
    memset(scanned_modules, 0, sizeof(scanned_modules));

    scan_known_sus_paths();

    for (int i = 0; persistence_files[i] != NULL; i++) {
        scan_active_config(persistence_files[i]);
    }
    for (int i = 0; persistence_directories[i] != NULL; i++) {
        scan_directory(persistence_directories[i], DIR_CONFIG, 3);
    }

    scan_directory("/boot/modules", DIR_MODULE, 0);

    return risk_score;
}

int
main(int argc, char **argv)
{
    int result;
    int print_score = 0;

    if (argc == 2 && strcmp(argv[1], "--score") == 0) {
        print_score = 1;

    } else if (argc != 1) {
        fprintf(stderr, "usage: %s [--score]\n", argv[0]);
        return 2;
    }

    result = persistence_detector_run();
    if (print_score)
        printf("%d\n", result);

    return result >= MIN_DETECTION_SCORE ? 1 : 0;
}
