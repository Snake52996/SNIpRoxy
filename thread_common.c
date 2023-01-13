#include "thread_common.h"
#define _GNU_SOURCE
#include <signal.h>
#include <pthread.h>
void maskSignals(){
    sigset_t sigset;
    sigfillset(&sigset);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);
}