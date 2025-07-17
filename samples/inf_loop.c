#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

pthread_mutex_t m;
//int nondet_int();
int x, y, z, balance;
_Bool deposit_done=0, withdraw_done=0;

void check() {
  if (balance >= 1000) {
    printf("?");
  }
}


void *loop1(void *arg) 
{
  while (x < 100000000) {
    x = x + 1;
    check();
  }
}

void *loop2(void *arg) 
{
  while (y < 100000000) {
    y = y + 1;
    check();
  }
}

int main() 
{
  printf("main started, PID: %d, Kernel TID: %ld\n", 
         getpid(), syscall(SYS_gettid));
  pthread_t t1, t2, t3;

  pthread_mutex_init(&m, 0);

  x = 1;
  y = 2;
  z = 4;
  balance = x;

  pthread_create(&t2, 0, loop1, 0);
  pthread_create(&t1, 0, loop2, 0);
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  return 0;
}
