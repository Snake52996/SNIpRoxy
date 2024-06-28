#include "thread_common.hh"
#include <pthread.h>
#include <signal.h>
void mask_signals() {
  sigset_t sigset;
  sigfillset(&sigset);
  pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}