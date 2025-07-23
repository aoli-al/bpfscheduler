#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#define NUM_THREADS 4
#define NUM_ITERATIONS 10

pthread_mutex_t mutex1 = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t mutex2 = PTHREAD_MUTEX_INITIALIZER;
int shared_counter = 0;

void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;
    
    for (int i = 0; i < NUM_ITERATIONS; i++) {
        printf("Thread %d: Attempting to lock mutex1 (iteration %d)\n", thread_id, i);
        pthread_mutex_lock(&mutex1);
        
        printf("Thread %d: Acquired mutex1, counter = %d\n", thread_id, shared_counter);
        shared_counter++;
        
        // Simulate some work
        usleep(10000); // 10ms
        
        // Try to acquire second mutex to create more lock contention
        if (i % 3 == 0) {
            printf("Thread %d: Attempting to lock mutex2\n", thread_id);
            pthread_mutex_lock(&mutex2);
            printf("Thread %d: Acquired mutex2\n", thread_id);
            usleep(5000); // 5ms
            pthread_mutex_unlock(&mutex2);
            printf("Thread %d: Released mutex2\n", thread_id);
        }
        
        pthread_mutex_unlock(&mutex1);
        printf("Thread %d: Released mutex1\n", thread_id);
        
        // Small delay between iterations
        usleep(1000);
    }
    
    printf("Thread %d: Completed all iterations\n", thread_id);
    return NULL;
}

int main() {
    pthread_t threads[NUM_THREADS];
    int thread_ids[NUM_THREADS];
    
    printf("Starting mutex test with %d threads, %d iterations each\n", NUM_THREADS, NUM_ITERATIONS);
    printf("This program will create mutex contention for testing the eBPF monitor\n");
    
    // Create threads
    for (int i = 0; i < NUM_THREADS; i++) {
        thread_ids[i] = i + 1;
        if (pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]) != 0) {
            perror("pthread_create");
            exit(1);
        }
    }
    
    // Wait for all threads to complete
    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    printf("Final counter value: %d (expected: %d)\n", shared_counter, NUM_THREADS * NUM_ITERATIONS);
    printf("Mutex test completed\n");
    
    pthread_mutex_destroy(&mutex1);
    pthread_mutex_destroy(&mutex2);
    
    return 0;
}