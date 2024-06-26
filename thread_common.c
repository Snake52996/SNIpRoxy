#include "thread_common.h"
#define _GNU_SOURCE
#include <pthread.h>
#include <signal.h>
void maskSignals() {
  sigset_t sigset;
  sigfillset(&sigset);
  pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}