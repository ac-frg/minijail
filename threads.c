#define _GNU_SOURCE
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include "libminijail.h"

void print_seccomp_status(pid_t tid)
{
	char filename[100];
	snprintf(filename, 100, "/proc/self/task/%d/status", tid);
	FILE *status = fopen(filename, "r");
	char *line = NULL;
	size_t n = 0;

	while (getline(&line, &n, status) != -1) {
		if (strstr(line, "Seccomp") != NULL) {
			printf("%d %s", tid, line);
		}
	}
	free(line);
	fclose(status);
}

void *set_tsync(void *aux)
{
	pid_t tid = syscall(SYS_gettid);
	printf("set_tsync: tid: %d\n", tid);
	struct minijail *j = minijail_new();
	minijail_no_new_privs(j);
	minijail_use_seccomp_filter(j);
	minijail_set_seccomp_filter_tsync(j);
	printf("set_tsync: before minijail_parse_seccomp_filters\n");
	minijail_parse_seccomp_filters(j, "test/thread.policy");
	sleep(1);
	minijail_enter(j);
	printf("inside minijail\n");
	print_seccomp_status(tid);
	return (void *)1;
}

void *thread2(void *aux)
{
	pid_t tid = syscall(SYS_gettid);
	printf("thread2: tid: %d\n", tid);
	print_seccomp_status(tid);
	sleep(3);
	print_seccomp_status(tid);
	printf("thread2: before prctl\n");
	prctl(PR_SET_NAME, "iwilldie");
	printf("thread2: after prctl\n");
	return (void *)2;
}

int main(int argc, char *argv[])
{
	pthread_t workers[2];
	pthread_attr_t attr;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	printf("main thread: tid: %ld\n", syscall(SYS_gettid));

	pthread_create(&workers[0], &attr, thread2, NULL);
	pthread_create(&workers[1], &attr, set_tsync, NULL);

	void *retvalp = calloc(1, sizeof(int));
	if (pthread_join(workers[0], &retvalp) == 0) {
		printf("thread2: join: %p\n", retvalp);
	} else {
		printf("thread2: join failed\n");
	}

	if (pthread_join(workers[1], &retvalp) == 0) {
		printf("set_tsync: join: %p\n", retvalp);
	} else {
		printf("set_tsync: join failed\n");
	}

	/* Clean up and exit. */
	pthread_exit(NULL);
}
