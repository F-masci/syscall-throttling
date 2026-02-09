#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <stdatomic.h>
#include <time.h>

#ifndef SYS_getppid
#define SYS_getppid 110
#endif

#define MIN_PRINT_ELAPSED_TIME_S 9
#define MIN_PRINT_ELAPSED_TIME_NS (MIN_PRINT_ELAPSED_TIME_S * 1000000000LL)

// Global variables
volatile int stop; // Flag to stop threads
atomic_long total_calls; // Atomic counter for statistics

// Function executed by threads
void *worker(void *arg)
{
	size_t idx = (size_t)arg;
	long local_calls = 0;

	struct timespec start, end;
	long long elapsed_ns;

	// Loop until main says stop
	while (!stop) {
		// Get start time
		clock_gettime(CLOCK_MONOTONIC, &start);

		// Run syscall
		if (syscall(SYS_getppid) == -1)
			perror("syscall failed");

		// Get end time
		clock_gettime(CLOCK_MONOTONIC, &end);

		// Calculate elapsed time in nanoseconds
		elapsed_ns = (end.tv_sec - start.tv_sec) * 1000000000LL + (end.tv_nsec - start.tv_nsec);

		// Print elapsed time
		if (elapsed_ns > MIN_PRINT_ELAPSED_TIME_NS)
			printf("(%zu) Syscall time: %.3f s (%lld ns)\n", idx, elapsed_ns / 1000000000.0, elapsed_ns);

		local_calls++;
	}

	// Update atomic total at the end
	atomic_fetch_add(&total_calls, local_calls);
	return NULL;
}

int main(int argc, char *argv[])
{
	// Check arguments
	if (argc < 3) {
		fprintf(stderr, "Usage: %s <num_threads> <duration_seconds>\n", argv[0]);
		return 1;
	}

	int num_threads = atoi(argv[1]);
	int duration = atoi(argv[2]);

	printf("Minimum print elapsed time: %d s\n", MIN_PRINT_ELAPSED_TIME_S);
	printf("Syscall number: %d\n", SYS_getppid);
	printf("Starting %d threads for %d seconds...\n", num_threads, duration);
	fflush(stdout);

	pthread_t *threads = malloc(sizeof(pthread_t) * num_threads);

	if (!threads) {
		perror("Malloc failed");
		return 1;
	}

	// Create Threads
	for (size_t i = 0; i < (size_t)num_threads; i++) {
		if (pthread_create(&threads[i], NULL, worker, (void *)i) != 0) {
			perror("Thread create failed");
			free(threads);
			return 1;
		}
	}

	// Wait for test duration
	sleep(duration);

	// Stop threads
	stop = 1;

	// Wait for threads to finish
	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);

	printf("Test complete. Total Syscalls invoked: %ld\n", atomic_load(&total_calls));

	free(threads);
	return 0;
}
