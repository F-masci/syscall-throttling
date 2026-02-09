#define _GNU_SOURCE
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <errno.h>
#include <signal.h>

void sigterm_handler(__attribute__((unused)) int signum) {
	printf("Received SIGTERM\n");
	fflush(stdout);
}

int main(void)
{

	struct timespec start, end;
	long long elapsed_ns;

	signal(SIGTERM, sigterm_handler);

	printf("Entering pause...\n");
	fflush(stdout);

	// Get start time
	clock_gettime(CLOCK_MONOTONIC, &start);

	errno = 0;
	pause();
	printf("Pause errno value: %d\n", errno);
	fflush(stdout);

	// Get end time
	clock_gettime(CLOCK_MONOTONIC, &end);

	// Calculate elapsed time in nanoseconds
	elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);

	// Print elapsed time
	printf("Pause time: %.3f s (%lld ns)\n", elapsed_ns / 1000000000.0, elapsed_ns);
	fflush(stdout);
	
	return 0;
}