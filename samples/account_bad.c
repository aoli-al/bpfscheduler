#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include <unistd.h>
#include <sys/syscall.h>

pthread_mutex_t m;
//int nondet_int();
int x, y, z, balance;
_Bool deposit_done=0, withdraw_done=0;

void *deposit(void *arg) 
{
  printf("deposit thread started, PID: %d, Kernel TID: %ld\n", 
         getpid(), syscall(SYS_gettid));
  pthread_mutex_lock(&m);
  printf("deposit start\n");
  balance = balance + y;
  deposit_done=1;
  printf("deposit stop\n");
  pthread_mutex_unlock(&m);
}

void *withdraw(void *arg) 
{
  printf("withdraw thread started, PID: %d, Kernel TID: %ld\n", 
         getpid(), syscall(SYS_gettid));
  pthread_mutex_lock(&m);
  printf("withdraw start\n");
  balance = balance - z;
  withdraw_done=1;
  printf("withdraw done\n");
  pthread_mutex_unlock(&m);
}

void *check_result(void *arg) 
{
  printf("check_result thread started, PID: %d, Kernel TID: %ld\n", 
         getpid(), syscall(SYS_gettid));
  pthread_mutex_lock(&m);
  printf("check result start\n");
  if (deposit_done && withdraw_done)
    assert(balance == (x - y) - z); /* BAD */
  printf("check result done\n");
  pthread_mutex_unlock(&m);
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

  pthread_create(&t3, 0, check_result, 0);
  pthread_create(&t1, 0, deposit, 0);
  pthread_create(&t2, 0, withdraw, 0);
  pthread_join(t1, NULL);
  pthread_join(t2, NULL);
  pthread_join(t3, NULL);
  return 0;
}
