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

// Include shared definitions
// Ensure this file contains the updated structs (list_query_t, etc.)
#include "../opsc.h" 
#include "errs.h"

#define DEFAULT_DEVICE "/dev/sct-monitor"
#define INITIAL_LIST_CAPACITY 32

// Enum defining the possible actions to perform
typedef enum {
    ACTION_NONE,
    ACTION_ADD,
    ACTION_REMOVE,
    ACTION_SET_LIMIT,
    ACTION_SET_STATUS,
    ACTION_SET_FAST_UNLOAD,
    ACTION_GET_STATUS,
    ACTION_GET_STATS,
    ACTION_GET_PEAK_DELAY,
    ACTION_GET_LIST
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
    
    printf("Configuration Commands:\n");
    printf("  add              Adds a monitoring rule (requires --sys, --uid, or --prog)\n");
    printf("  remove           Removes a monitoring rule (requires --sys, --uid, or --prog)\n");
    printf("  limit            Set the max syscall invocations limit (requires --val)\n");
    printf("  status           Set the monitor status 1=ON, 0=OFF (requires --val)\n");
    printf("  fast-unload      Set the fast unload status 1=ON, 0=OFF (requires --val)\n\n");

    printf("Reading Commands:\n");
    printf("  get-status       Get general monitor status\n");
    printf("  get-stats        Get throttling statistics\n");
    printf("  get-delay        Get peak delay information\n");
    printf("  get-list         Get list of monitored items (requires --sys, --uid, or --prog)\n\n");

    printf("Options:\n");
    printf("  --sys <nr>       Specifies the system call number\n");
    printf("  --uid <id>       Specifies the User ID\n");
    printf("  --prog <name>    Specifies the process name\n");
    printf("  --val <num>      Specifies a numeric value (for limit/status/fast-unload)\n");
    printf("  --dev <path>     Specifies the device path (Default: %s)\n", DEFAULT_DEVICE);
    printf("  -h, --help       Show this help message\n\n");
    
    printf("Examples:\n");
    printf("  %s add --sys 59\n", prog_name);
    printf("  %s limit --val 100\n", prog_name);
    printf("  %s add --prog mkdir\n", prog_name);
    printf("  %s get-list --uid\n", prog_name);
    printf("  %s fast-unload --val 0\n", prog_name);
}

// Helper function to handle list retrieval with dynamic reallocation
int handle_get_list(int fd, target_type_t type) {
    unsigned long req;
    size_t item_size;
    
    switch (type) {
        case TARGET_SYSCALL: req = SCT_IOCTL_GET_SYSCALL_LIST; item_size = sizeof(scidx_t); break;
        case TARGET_UID:     req = SCT_IOCTL_GET_UID_LIST;     item_size = sizeof(uid_t); break;
        case TARGET_PROG:    req = SCT_IOCTL_GET_PROG_LIST;    item_size = PATH_MAX; break; // Fixed size strings
        default: return -1;
    }

    // Prepare query structure
    list_query_t query;
    query.max_items = INITIAL_LIST_CAPACITY;
    query.ptr = calloc(query.max_items, item_size);
    if (!query.ptr) {
        perror("Error allocating memory");
        return MEMORY_ALLOCATION_ERROR;
    }

    // First attempt
    if (ioctl(fd, req, &query) < 0) {
        perror("Error ioctl get list");
        free(query.ptr);
        return IOCTL_EXECUTION_ERROR;
    }

    // Check if we need to resize
    if (query.real_items > query.fetched_items) {
        printf("[Client] Buffer too small (fetched %zu/%zu). Reallocating...\n", query.fetched_items, query.real_items);
        
        free(query.ptr);
        query.max_items = query.real_items;
        query.ptr = calloc(query.max_items, item_size);
        if (!query.ptr) return MEMORY_ALLOCATION_ERROR;

        // Second attempt
        if (ioctl(fd, req, &query) < 0) {
            perror("Error ioctl get list retry");
            free(query.ptr);
            return IOCTL_EXECUTION_ERROR;
        }
    }

    // Print results
    char *current_ptr = (char *) query.ptr;
    printf("Fetched %zu items (Total available: %zu):\n", query.fetched_items, query.real_items);
    for (size_t i = 0; i < query.fetched_items; i++) {
        if (type == TARGET_SYSCALL) {
            printf("  - [%zu] Syscall: %d\n", i, ((scidx_t*)query.ptr)[i]);
        } else if (type == TARGET_UID) {
            printf("  - [%zu] UID: %u\n", i, ((uid_t*)query.ptr)[i]);
        } else if (type == TARGET_PROG) {
            // Calculate pointer to the i-th string
            printf("  - [%zu] Program: %s\n", i, current_ptr);
            current_ptr += strlen(current_ptr) + 1;
        }
    }

    free(query.ptr);
    return 0;
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
    // FIX: Changed optional_argument to required_argument to support space separation (e.g., --prog mkdir)
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
    // FIX: Removed double colons (::) to enforce required arguments
    while ((opt = getopt_long(argc, argv, "d:s:u:p:v:h", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'd':
                cfg.device_path = optarg;
                break;
            case 's':
                cfg.target_type = TARGET_SYSCALL;
                if (optarg) cfg.value.syscall_nr = atoi(optarg);
                break;
            case 'u':
                cfg.target_type = TARGET_UID;
                if (optarg) cfg.value.uid = (unsigned int)strtoul(optarg, NULL, 10);
                break;
            case 'p':
                cfg.target_type = TARGET_PROG;
                if (optarg) cfg.value.prog_name = optarg;
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
        } else if (strcmp(argv[optind], "fast-unload") == 0) {
            cfg.action = ACTION_SET_FAST_UNLOAD;
        } else if (strcmp(argv[optind], "get-status") == 0) {
            cfg.action = ACTION_GET_STATUS;
        } else if (strcmp(argv[optind], "get-stats") == 0) {
            cfg.action = ACTION_GET_STATS;
        } else if (strcmp(argv[optind], "get-delay") == 0) {
            cfg.action = ACTION_GET_PEAK_DELAY;
        } else if (strcmp(argv[optind], "get-list") == 0) {
            cfg.action = ACTION_GET_LIST;
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
        // Add/Remove require a specific target AND a value
        if (cfg.target_type == TARGET_NONE || cfg.target_type == TARGET_GENERIC_VAL) {
            fprintf(stderr, "Error: For add/remove you must specify --sys <val>, --uid <val>, or --prog <val>.\n");
            return INVALID_ARGUMENTS_ERROR;
        }
        // Basic check for empty optional args
        if (cfg.target_type == TARGET_PROG && !cfg.value.prog_name) {
            fprintf(stderr, "Error: Program name missing.\n");
            return INVALID_ARGUMENTS_ERROR;
        }
    } 
    else if (cfg.action == ACTION_GET_LIST) {
        // Get list requires target type.
        // NOTE: Since arguments are now required, users might need to pass a dummy value
        // e.g., "get-list --prog x" if they want to list programs.
        if (cfg.target_type == TARGET_NONE || cfg.target_type == TARGET_GENERIC_VAL) {
            fprintf(stderr, "Error: For get-list you must specify --sys, --uid, or --prog (with any dummy value).\n");
            return INVALID_ARGUMENTS_ERROR;
        }
    }
    else if (cfg.action == ACTION_SET_LIMIT || cfg.action == ACTION_SET_STATUS || cfg.action == ACTION_SET_FAST_UNLOAD) {
        // Limit/Status/Fast Unload require a generic numeric value
        if (cfg.target_type != TARGET_GENERIC_VAL) {
            fprintf(stderr, "Error: For limit/status/fast-unload you must specify --val <number>.\n");
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

    // Output structures
    monitor_status_t status_info;
    throttling_stats_t stats_info;
    sysc_delayed_t delay_info;

    // Determine the correct IOCTL request and argument pointer
    switch(cfg.action) {
        /* --- WRITE OPERATIONS --- */
        case ACTION_ADD:
            if (cfg.target_type == TARGET_SYSCALL) {
                req = SCT_IOCTL_ADD_SYSCALL; arg_ptr = &cfg.value.syscall_nr;
                printf("[Client] Adding syscall: %d\n", cfg.value.syscall_nr);
            } else if (cfg.target_type == TARGET_UID) {
                req = SCT_IOCTL_ADD_UID; arg_ptr = &cfg.value.uid;
                printf("[Client] Adding UID: %u\n", cfg.value.uid);
            } else if (cfg.target_type == TARGET_PROG) {
                req = SCT_IOCTL_ADD_PROG; arg_ptr = cfg.value.prog_name;
                printf("[Client] Adding prog name: %s\n", cfg.value.prog_name);
            }
            break;

        case ACTION_REMOVE:
            if (cfg.target_type == TARGET_SYSCALL) {
                req = SCT_IOCTL_DEL_SYSCALL; arg_ptr = &cfg.value.syscall_nr;
                printf("[Client] Removing syscall: %d\n", cfg.value.syscall_nr);
            } else if (cfg.target_type == TARGET_UID) {
                req = SCT_IOCTL_DEL_UID; arg_ptr = &cfg.value.uid;
                printf("[Client] Removing UID: %u\n", cfg.value.uid);
            } else if (cfg.target_type == TARGET_PROG) {
                req = SCT_IOCTL_DEL_PROG; arg_ptr = cfg.value.prog_name;
                printf("[Client] Removing prog name: %s\n", cfg.value.prog_name);
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

        case ACTION_SET_FAST_UNLOAD:
            req = SCT_IOCTL_SET_FAST_UNLOAD;
            arg_ptr = &cfg.value.status;
            printf("[Client] Setting fast unload to: %s\n", cfg.value.status ? "ON" : "OFF");
            break;

        /* --- READ OPERATIONS --- */
        case ACTION_GET_STATUS:
            req = SCT_IOCTL_GET_STATUS;
            arg_ptr = &status_info;
            printf("[Client] Getting monitor status...\n");
            break;

        case ACTION_GET_STATS:
            req = SCT_IOCTL_GET_STATS;
            arg_ptr = &stats_info;
            printf("[Client] Getting throttling statistics...\n");
            break;

        case ACTION_GET_PEAK_DELAY:
            req = SCT_IOCTL_GET_PEAK_DELAY;
            arg_ptr = &delay_info;
            printf("[Client] Getting peak delay information...\n");
            break;
        
        case ACTION_GET_LIST:
            // Special handling because of dynamic allocation
            close(fd);
            return handle_get_list(open(cfg.device_path, O_RDWR), cfg.target_type);

        default:
            break;
    }

    // Perform the IOCTL call
    if (ioctl(fd, req, arg_ptr) < 0) {
        perror("Error ioctl");
        close(fd);
        return IOCTL_EXECUTION_ERROR;
    }

    // Post-execution printing for read commands
    switch (cfg.action) {
        case ACTION_GET_STATUS:
            printf("========= MONITOR STATUS =========\n");
            printf("Enabled:     %s\n", status_info.enabled ? "YES" : "NO");
            printf("Fast Unload: %s\n", status_info.fast_unload ? "YES" : "NO");
            printf("Max Invoks:  %lu\n", status_info.max_invoks);
            printf("Cur Invoks:  %lu\n", status_info.cur_invoks);
            printf("Window:      %lu sec\n", status_info.window_sec);
            printf("==================================\n");
            break;

        case ACTION_GET_STATS:
            printf("======== THROTTLING STATS ========\n");
            printf("Peak Blocked Threads: %lu\n", stats_info.peak_blocked);
            printf("Avg Blocked Threads:  %lu.%02lu\n", stats_info.avg_blocked_int, stats_info.avg_blocked_dec);
            printf("==================================\n");
            break;

        case ACTION_GET_PEAK_DELAY:
            printf("========= PEAK DELAY INFO ========\n");
            if (delay_info.syscall > -1) {
                printf("Delay:      %ld ms\n", delay_info.delay_ms);
                printf("Syscall:    %d\n", delay_info.syscall);
                printf("UID:        %u\n", delay_info.uid);
                printf("Program:    %s\n", delay_info.prog_name);
            } else {
                printf("No delay recorded yet.\n");
            }
            printf("==================================\n");
            break;

        default:
            printf("[Client] Operation completed successfully.\n");
            break;
    }

    close(fd);
    return 0;
}