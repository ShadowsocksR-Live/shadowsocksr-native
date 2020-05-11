#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#define NUM_THREADS     5

void* perform_work(void* argument)
{
    int passed_in_value;

    passed_in_value = *((int*)argument);
    printf("Hello World! It's me, thread with argument %d!\n", passed_in_value);

    /* optionally: insert more useful stuff here */

    return NULL;
}

int main(int argc, char** argv)
{
    pthread_t threads[NUM_THREADS];
    int thread_args[NUM_THREADS];
    int result_code;
    unsigned index;

    // create all threads one by one
    for (index = 0; index < NUM_THREADS; ++index)
    {
        thread_args[index] = index;
        printf("In main: creating thread %d\n", index);
        result_code = pthread_create(&threads[index], NULL, perform_work, &thread_args[index]);
        assert(!result_code);
    }

    // wait for each thread to complete
    for (index = 0; index < NUM_THREADS; ++index)
    {
        // block until thread 'index' completes
        result_code = pthread_join(threads[index], NULL);
        assert(!result_code);
        printf("In main: thread %d has completed\n", index);
    }

    printf("In main: All threads completed successfully\n");
    //exit( EXIT_SUCCESS );
}
