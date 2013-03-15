#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "utils.h"

void FATAL(const char *msg) {
    fprintf(stderr, "%s", msg);
    exit(-1);
}

void usage() {
    printf("usage: ss  -s server_host -p server_port -l local_port\n");
    printf("           -k password [-m encrypt_method] [-f pid_file]\n");
    printf("\n");
    printf("options:\n");
    printf("       encrypt_method:  table, rc4\n");
    printf("       pid_file:        valid path to the pid file\n");
}

void demonize(const char* path) {

    /* Our process ID and Session ID */
    pid_t pid, sid;

    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }

    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
        FILE *file = fopen(path, "w");
        if (file == NULL) FATAL("Invalid pid file\n");

        fprintf(file, "%d", pid);
        fclose(file);
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);

    /* Open any logs here */        

    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

}

