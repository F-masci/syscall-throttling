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

#include "../opsc.h"
#include "errs.h"

#define DEFAULT_DEVICE "/dev/sct-monitor"

// Enum defining the possible actions to perform
typedef enum {
    ACTION_NONE,
    ACTION_ADD,
    ACTION_REMOVE,
    ACTION_SET_LIMIT,
    ACTION_SET_STATUS
} action_t;

// Enum defining the type of data being targeted
typedef enum {
    TARGET_NONE,
    TARGET_SYSCALL,
    TARGET_UID,
    TARGET_PROG,
    TARGET_GENERIC_VAL
} target_type_t;

// Configuration structure holding parsed arguments
struct config {
    char *device_path;
    action_t action;
    target_type_t target_type;
    
    union {
        int syscall_nr;
        unsigned int uid;
        char *prog_name;
        unsigned long limit;
        int status;
    } value;
};

void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS] <command>\n\n", prog_name);
    printf("Description:\n");
    printf("  Client to configure the System Call Throttling module.\n\n");
    printf("Commands:\n");
    printf("  add              Adds a monitoring rule\n");
    printf("  remove           Removes a monitoring rule\n");
    printf("  limit            Set the max syscall invocations limit\n");
    printf("  status           Set the monitor status (1=ON, 0=OFF)\n\n");
    printf("Options:\n");
    printf("  --sys <nr>       Specifies the system call number\n");
    printf("  --uid <id>       Specifies the User ID\n");
    printf("  --prog <name>    Specifies the process name\n");
    printf("  --val <num>      Specifies a numeric value (for limit/status)\n");
    printf("  --dev <path>     Specifies the device path (Default: %s)\n", DEFAULT_DEVICE);
    printf("  -h, --help       Show this help message\n\n");
    printf("Examples:\n");
    printf("  %s add --sys 59\n", prog_name);
    printf("  %s limit --val 100\n", prog_name);
    printf("  %s status --val 0\n", prog_name);
}

int main(int argc, char **argv) {

    // Setup default configuration
    struct config cfg = {
        .device_path    = DEFAULT_DEVICE,
        .action         = ACTION_NONE,
        .target_type    = TARGET_NONE
    };

    int opt;
    int option_index = 0;

    // Long options structure
    static struct option long_options[] = {
        {"dev",  required_argument, 0, 'd'},
        {"sys",  required_argument, 0, 's'},
        {"uid",  required_argument, 0, 'u'},
        {"prog", required_argument, 0, 'p'},
        {"val",  required_argument, 0, 'v'},
        {"help", no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    // Parsing command-line arguments
    while ((opt = getopt_long(argc, argv, "d:s:u:p:v:h", long_options, &option_index)) != -1) {
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
            case 'v':
                cfg.target_type = TARGET_GENERIC_VAL;
                cfg.value.limit = strtoul(optarg, NULL, 10); 
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return INVALID_ARGUMENTS_ERROR;
        }
    }

    // Action parsing (commands are positional arguments)
    if (optind < argc) {
        if (strcmp(argv[optind], "add") == 0) {
            cfg.action = ACTION_ADD;
        } else if (strcmp(argv[optind], "remove") == 0) {
            cfg.action = ACTION_REMOVE;
        } else if (strcmp(argv[optind], "limit") == 0) {
            cfg.action = ACTION_SET_LIMIT;
        } else if (strcmp(argv[optind], "status") == 0) {
            cfg.action = ACTION_SET_STATUS;
        } else {
            fprintf(stderr, "Error: Unknown action '%s'.\n", argv[optind]);
            return INVALID_ARGUMENTS_ERROR;
        }
    } else {
        fprintf(stderr, "Error: No action specified.\n");
        print_usage(argv[0]);
        return INVALID_ARGUMENTS_ERROR;
    }

    // Validations logic
    if (cfg.action == ACTION_ADD || cfg.action == ACTION_REMOVE) {
        // Add/Remove require a specific target (Syscall, UID, or Prog)
        if (cfg.target_type == TARGET_NONE || cfg.target_type == TARGET_GENERIC_VAL) {
            fprintf(stderr, "Error: For add/remove you must specify --sys, --uid, or --prog.\n");
            return INVALID_ARGUMENTS_ERROR;
        }
    } 
    else if (cfg.action == ACTION_SET_LIMIT || cfg.action == ACTION_SET_STATUS) {
        // Limit/Status require a generic numeric value
        if (cfg.target_type != TARGET_GENERIC_VAL) {
            fprintf(stderr, "Error: For limit/status you must specify --val <number>.\n");
            return INVALID_ARGUMENTS_ERROR;
        }
        
        // If the action is status, cast the parsed long value to int
        if (cfg.action == ACTION_SET_STATUS) {
            cfg.value.status = (int) cfg.value.limit; 
        }
    }

    // Device open
    int fd = open(cfg.device_path, O_RDWR);
    if (fd < 0) {
        perror("Error opening device");
        fprintf(stderr, "Check that the module is loaded and that the path '%s' is correct.\n", cfg.device_path);
        return DEVICE_OPEN_ERROR;
    }

    // IOCTL execution preparation
    unsigned long req = 0;
    void *arg_ptr = NULL;

    // Determine the correct IOCTL request and argument pointer
    switch(cfg.action) {
        case ACTION_ADD:
            if (cfg.target_type == TARGET_SYSCALL) {
                req = SCT_IOCTL_ADD_SYSCALL; arg_ptr = &cfg.value.syscall_nr;
            } else if (cfg.target_type == TARGET_UID) {
                req = SCT_IOCTL_ADD_UID; arg_ptr = &cfg.value.uid;
            } else if (cfg.target_type == TARGET_PROG) {
                req = SCT_IOCTL_ADD_PROG; arg_ptr = cfg.value.prog_name;
            }
            break;

        case ACTION_REMOVE:
            if (cfg.target_type == TARGET_SYSCALL) {
                req = SCT_IOCTL_DEL_SYSCALL; arg_ptr = &cfg.value.syscall_nr;
            } else if (cfg.target_type == TARGET_UID) {
                req = SCT_IOCTL_DEL_UID; arg_ptr = &cfg.value.uid;
            } else if (cfg.target_type == TARGET_PROG) {
                req = SCT_IOCTL_DEL_PROG; arg_ptr = cfg.value.prog_name;
            }
            break;

        case ACTION_SET_LIMIT:
            req = SCT_IOCTL_SET_LIMIT;
            arg_ptr = &cfg.value.limit;
            printf("[Client] Setting limit to: %lu\n", cfg.value.limit);
            break;

        case ACTION_SET_STATUS:
            req = SCT_IOCTL_SET_STATUS;
            arg_ptr = &cfg.value.status;
            printf("[Client] Setting status to: %s\n", cfg.value.status ? "ON" : "OFF");
            break;
            
        default:
            break;
    }

    // Perform the IOCTL call
    if (ioctl(fd, req, arg_ptr) < 0) {
        perror("Error ioctl");
        close(fd);
        return IOCTL_EXECUTION_ERROR;
    }

    printf("[Client] Operation completed successfully.\n");
    close(fd);
    return 0;
}