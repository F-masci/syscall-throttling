#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include <stdlib.h> 
#include <time.h>
#include "../ops.h"

const char *fake_progs[] = {
    "vim", "bash", "gcc", "python3", "sshd", 
    "systemd", "nginx", "docker", "gdb", "htop"
};
int num_progs = sizeof(fake_progs) / sizeof(fake_progs[0]);

int main(int argc, char **argv) {
    
    if(argc < 2) {
        printf("Usage: %s <device>\n", argv[0]);
        return 1;
    }

    // TODO: Check input values

    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("Errore open");
        return 1;
    }

    srand(time(NULL) ^ getpid());

    pid_t my_pid = (rand() % 32000) + 100;
    uint64_t my_syscall = rand() % 400;
    char *name = (char *)fake_progs[rand() % num_progs];

    // Send data
    ioctl(fd, SCT_IOCTL_ADD_UID, &my_pid);
    ioctl(fd, SCT_IOCTL_ADD_SYSCALL, &my_syscall);
    ioctl(fd, SCT_IOCTL_ADD_PROG, name);

    printf("[Client] Data sent to device %s:\n", argv[1]);
    printf("  -> PID inviato:     %d\n", my_pid);
    printf("  -> Syscall inviata: %lu\n", my_syscall);
    printf("  -> Programma inviato: \"%s\"\n", name);

    close(fd);
    return 0;
}