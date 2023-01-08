#ifndef SNIPROXY_COMMON_H_
#define SNIPROXY_COMMON_H_
#include <assert.h>
#define CHECK(x) assert((x)>=0)
#define LOOP_CHECK(rval, cmd) do{\
    rval = cmd;\
}while(rval == GNUTLS_E_AGAIN || rval == GNUTLS_E_INTERRUPTED)
#endif