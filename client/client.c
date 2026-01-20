#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>

#include "../ops.h"

#define DEFAULT_DEVICE "/dev/sct-monitor"

typedef enum {
    ACTION_NONE,
    ACTION_ADD,
    ACTION_REMOVE
} action_t;

typedef enum {
    TARGET_NONE,
    TARGET_SYSCALL,
    TARGET_UID,
    TARGET_PROG
} target_type_t;

struct config {
    char *device_path;
    action_t action;
    target_type_t target_type;
    
    // Valori union per memorizzare l'argomento parsato
    union {
        int syscall_nr;
        unsigned int uid;
        char *prog_name;
    } value;
};

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] <add|remove>\n\n", prog_name);
    printf("Description:\n");
    printf("  Client to configure the System Call Throttling module.\n\n");
    printf("Commands (required):\n");
    printf("  add                 Adds a monitoring rule\n");
    printf("  remove              Removes a monitoring rule\n\n");
    printf("Target Options (required):\n");
    printf("  --sys <nr>          Specifies the system call number\n");
    printf("  --uid <id>          Specifies the User ID\n");
    printf("  --prog <name>       Specifies the process name\n\n");
    printf("Other Options:\n");
    printf("  --dev <path>        Specifies the device path (Default: %s)\n", DEFAULT_DEVICE);
    printf("  -h, --help          Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s add --sys 59\n", prog_name);
    printf("  %s remove --prog vim --dev /dev/sct_custom\n", prog_name);
}

int main(int argc, char **argv) {

    // Setup default configuration
    struct config cfg = {
        .device_path = DEFAULT_DEVICE,
        .action = ACTION_NONE,
        .target_type = TARGET_NONE
    };

    int opt;
    int option_index = 0;

    // Long options structure
    static struct option long_options[] = {
        {"dev",  required_argument, 0, 'd'},
        {"sys",  required_argument, 0, 's'},
        {"uid",  required_argument, 0, 'u'},
        {"prog", required_argument, 0, 'p'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Parsing command-line arguments
    while ((opt = getopt_long(argc, argv, "d:s:u:p:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                cfg.device_path = optarg;
                break;
            case 's':
                cfg.target_type = TARGET_SYSCALL;
                cfg.value.syscall_nr = atoi(optarg);
                break;
            case 'u':
                cfg.target_type = TARGET_UID;
                cfg.value.uid = (unsigned int)strtoul(optarg, NULL, 10);
                break;
            case 'p':
                cfg.target_type = TARGET_PROG;
                cfg.value.prog_name = optarg;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Action parsing
    if (optind < argc) {
        if (strcmp(argv[optind], "add") == 0) {
            cfg.action = ACTION_ADD;
        } else if (strcmp(argv[optind], "remove") == 0) {
            cfg.action = ACTION_REMOVE;
        } else {
            fprintf(stderr, "Error: Unknown action '%s'. Use 'add' or 'remove'.\n", argv[optind]);
            return 1;
        }
    } else {
        fprintf(stderr, "Error: No action specified (add/remove).\n");
        print_usage(argv[0]);
        return 1;
    }

    // Validations
    if (cfg.target_type == TARGET_NONE) {
        fprintf(stderr, "Error: You must specify a target (--sys, --uid, or --prog).\n");
        return 1;
    }

    // Device open
    int fd = open(cfg.device_path, O_RDWR);
    if (fd < 0) {
        perror("Error opening device");
        fprintf(stderr, "Check that the module is loaded and that the path '%s' is correct.\n", cfg.device_path);
        return 1;
    }

    // IOCTL execution
    unsigned long req = 0;
    void *arg_ptr = NULL;
    const char *type_str = "";

    // Request selection based on action and target
    switch(cfg.action) {
        case ACTION_ADD:
            switch (cfg.target_type) {
                case TARGET_SYSCALL:
                    req = SCT_IOCTL_ADD_SYSCALL;
                    arg_ptr = &cfg.value.syscall_nr;
                    type_str = "Syscall";
                break;
                case TARGET_UID:
                    req = SCT_IOCTL_ADD_UID;
                    arg_ptr = &cfg.value.uid;
                    type_str = "UID";
                    break;
                case TARGET_PROG:
                    req = SCT_IOCTL_ADD_PROG;
                    arg_ptr = cfg.value.prog_name;
                    type_str = "Program";
                    break;
                default:
                    fprintf(stderr, "Not valid target type\n");
                    close(fd);
                    return 1;
            }
            break;
        case ACTION_REMOVE:
            switch (cfg.target_type) {
                case TARGET_SYSCALL:
                    req = SCT_IOCTL_DEL_SYSCALL;
                    arg_ptr = &cfg.value.syscall_nr;
                    type_str = "Syscall";
                    break;
                case TARGET_UID:
                    req = SCT_IOCTL_DEL_UID;
                    arg_ptr = &cfg.value.uid;
                    type_str = "UID";
                    break;
                case TARGET_PROG:
                    req = SCT_IOCTL_DEL_PROG;
                    arg_ptr = cfg.value.prog_name;
                    type_str = "Program";
                    break;
                default:
                    fprintf(stderr, "Not valid target type\n");
                    close(fd);
                    return 1;
            }
            break;
        default:
            fprintf(stderr, "Not valid action\n");
            close(fd);
            return 1;
    }

    // Perform ioctl
    printf("[Client] Sending command to kernel...\n");
    printf("  -> Device: %s\n", cfg.device_path);
    printf("  -> Action: %s\n", (cfg.action == ACTION_ADD) ? "ADD" : "REMOVE");
    
    if (cfg.target_type == TARGET_PROG)
        printf("  -> Target: %s \"%s\"\n", type_str, cfg.value.prog_name);
    else if (cfg.target_type == TARGET_UID)
        printf("  -> Target: %s %u\n", type_str, cfg.value.uid);
    else
        printf("  -> Target: %s %d\n", type_str, cfg.value.syscall_nr);

    if (ioctl(fd, req, arg_ptr) < 0) {
        perror("Error ioctl");
        close(fd);
        return 1;
    }

    printf("[Client] Operation completed successfully.\n");

    close(fd);
    return 0;
}