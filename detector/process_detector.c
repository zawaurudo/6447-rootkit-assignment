
#include <sys/types.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/time.h>
#include <sys/user.h>

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#define DEFAULT_PID_MAX 99999
#define MAX_PID 1000000
#define MAX_BUFFER_SIZE (256U * 1024U * 1024U)

struct suspect_process {
    struct timeval start_time;
    int found_via_query;
    int found_via_signal;
    int found_via_file_table;
};

static int detected = 0;

static const char *sus_names[] = {
    "kmod_remote_listen",
    "revshell",
    "reverse_shell",
    "rklog",
    "hide_kld",
    NULL
};

static int is_sus_name(const char *name) {
    if (name == NULL)
        return 0;

    for (int i = 0; sus_names[i] != NULL; i++) {
        if (strcasecmp(name, sus_names[i]) == 0)
            return 1;
    }
    return 0;
}

static void
report_sus_process(int pid, const char *reason)
{
    printf("[!] Suspicious process: PID %d (%s)\n", pid, reason);
    detected = 1;
}

static void * read_sysctl(const int *mib, int mib_len, size_t *size) {
    void *buffer = NULL;
    size_t needed = 0;

    *size = 0;

    if (sysctl(mib, mib_len, NULL, &needed, NULL, 0) == -1) {
        return NULL;
    }

    if (needed > MAX_BUFFER_SIZE) {
        return NULL;
    }

    size_t capacity = needed + needed / 4 + 4096;

    if (capacity > MAX_BUFFER_SIZE) {
        capacity = MAX_BUFFER_SIZE;
    }

    for (int attempt = 0; attempt < 8; attempt++) {
        void *new_buffer = realloc(buffer, capacity);

        if (new_buffer == NULL) {
            free(buffer);
            return NULL;
        }

        buffer = new_buffer;

        size_t len = capacity;

        if (sysctl(mib, mib_len, buffer, &len, NULL, 0) == 0) {
            *size = len;
            return buffer;
        }

        if (errno != ENOMEM)
            break;

        if (capacity == MAX_BUFFER_SIZE)
            break;

        if (capacity > MAX_BUFFER_SIZE / 2)
            capacity = MAX_BUFFER_SIZE;
        else
            capacity *= 2;
    }

    free(buffer);
    return NULL;
}

static int
get_processes(unsigned char *seen, int pid_max)
{
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PROC };
    size_t bytes;
    memset(seen, 0, pid_max + 1);

    struct kinfo_proc *processes = read_sysctl(mib, 3, &bytes);

    if (processes == NULL) {
        return -1;
    }

    if (bytes % sizeof(struct kinfo_proc) != 0) {
        free(processes);
        return -1;
    }

    int count = bytes / sizeof(struct kinfo_proc);

    for (int i = 0; i < count; i++) {
        struct kinfo_proc *proc = &processes[i];

        if (proc->ki_structsize != sizeof(struct kinfo_proc)) {
            continue;
        }

        if (proc->ki_pid >= 1 && proc->ki_pid <= pid_max) {
            seen[proc->ki_pid] = 1;
        }

        if (is_sus_name(proc->ki_comm))
            report_sus_process(proc->ki_pid, "suspicious name");
    }

    free(processes);
    return 0;
}

static int get_process_by_pid(int pid, struct kinfo_proc *process) {
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
    size_t size = sizeof(*process);

    memset(process, 0, sizeof(*process));

    if (sysctl(mib, 4, process, &size, NULL, 0) == -1 ||
        size != sizeof(*process) ||
        process->ki_structsize != sizeof(*process) ||
        process->ki_pid != pid) {
        return 0;
    }

    return 1;
}

static int does_process_exist(int pid) {
    if (kill(pid, 0) == 0) {
        return 1;
    }
    return errno == EPERM;
}

static int get_file_owners(unsigned char *owners, int pid_max) {
    int mib[] = { CTL_KERN, KERN_FILE };
    size_t bytes;

    memset(owners, 0, pid_max + 1);

    struct xfile *files = read_sysctl(mib, 2, &bytes);

    if (files == NULL) {
        return -1;
    }

    if (bytes % sizeof(struct xfile) != 0) {
        free(files);
        return -1;
    }

    int count = bytes / sizeof(struct xfile);

    for (int i = 0; i < count; i++) {
        if (files[i].xf_size != sizeof(struct xfile)) {
            continue;
        }

        int pid = files[i].xf_pid;

        if (pid >= 1 && pid <= pid_max) {
            owners[pid] = 1;
        }
    }

    free(files);
    return 0;
}

static int get_max_possible_pid(void) {
    int pid_max = DEFAULT_PID_MAX;
    size_t size = sizeof(pid_max);

    if (sysctlbyname("kern.pid_max", &pid_max, &size, NULL, 0) == -1 ||
        size != sizeof(pid_max) ||
        pid_max < 1 || pid_max > MAX_PID) {
        return DEFAULT_PID_MAX;
    }

    return pid_max;
}

static int scan_processes(void) {
    int pid_max = get_max_possible_pid();
    size_t size = (size_t)pid_max + 1;

    unsigned char *process1 = calloc(size, 1);
    unsigned char *process2 = calloc(size, 1);
    unsigned char *process3 = calloc(size, 1);
    unsigned char *files1 = calloc(size, 1);
    unsigned char *files2 = calloc(size, 1);

    struct suspect_process *sus_processes =
        calloc(size, sizeof(struct suspect_process));

    struct kinfo_proc proc;
    int files_available = 0;

    if (!process1 || !process2 || !process3 ||
        !files1 || !files2 || !sus_processes) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }

    if (get_processes(process1, pid_max) == -1) {
        fprintf(stderr, "Failed to get process list\n");
        goto cleanup;
    }

    if (detected)
        goto cleanup;

    for (int pid = 1; pid <= pid_max; pid++) {
        if (!get_process_by_pid(pid, &proc))
            continue;

        if (is_sus_name(proc.ki_comm)) {
            report_sus_process(pid, "suspicious name");
            goto cleanup;
        }

        if (!process1[pid]) {
            sus_processes[pid].found_via_query = 1;
            sus_processes[pid].start_time = proc.ki_start;
            sus_processes[pid].found_via_signal = does_process_exist(pid);
        }
    }

    files_available = (get_file_owners(files1, pid_max) == 0);

    if (files_available) {
        for (int pid = 1; pid <= pid_max; pid++) {
            if (!process1[pid] && files1[pid]) {
                sus_processes[pid].found_via_file_table = 1;

                if (does_process_exist(pid))
                    sus_processes[pid].found_via_signal = 1;
            }
        }
    }

    if (get_processes(process2, pid_max) == -1) {
        fprintf(stderr, "Failed to get second process list\n");
        goto cleanup;
    }

    for (int pid = 1; pid <= pid_max; pid++) {
        if (!sus_processes[pid].found_via_query)
            continue;

        if (process2[pid])
            continue;

        if (!get_process_by_pid(pid, &proc))
            continue;

        if (is_sus_name(proc.ki_comm))
            report_sus_process(pid, "suspicious name");

        if (sus_processes[pid].start_time.tv_sec == proc.ki_start.tv_sec &&
            sus_processes[pid].start_time.tv_usec == proc.ki_start.tv_usec) {
            report_sus_process(pid, "hidden from process list");
        }
    }

    if (files_available &&
        get_file_owners(files2, pid_max) == 0 &&
        get_processes(process3, pid_max) == 0) {

        for (int pid = 1; pid <= pid_max; pid++) {
            if (!sus_processes[pid].found_via_file_table)
                continue;

            if (!sus_processes[pid].found_via_signal)
                continue;

            if (!files2[pid])
                continue;

            if (process1[pid] || process2[pid] || process3[pid])
                continue;

            if (!does_process_exist(pid))
                continue;

            report_sus_process(pid, "hidden process owns open files");
        }
    }

cleanup:
    free(process1);
    free(process2);
    free(process3);
    free(files1);
    free(files2);
    free(sus_processes);

    return detected;
}

int
main(void)
{
    if (scan_processes()) {
        return 1;
    }

    return 0;
}
