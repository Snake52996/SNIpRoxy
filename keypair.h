#ifndef SNIPROXY_KEYPAIR_H_
#define SNIPROXY_KEYPAIR_H_
#define _GNU_SOURCE
#include <baSe/RAII.h>
#include <baSe/hashtable.h>
#include <baSe/keyvalue_pair.h>
#include <gnutls/gnutls.h>
#include <gnutls/abstract.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
struct keypair{
    RAII _;
    char* hostname;
    gnutls_pcert_st cert;
    gnutls_privkey_t key;
    atomic_uint references; 
};
struct certificate_table{
    HashTable table;
};
unsigned int keypair_key_hash(const void* key);
void certificate_table_init(struct certificate_table* table, size_t slots);
struct keypair* certificate_table_prepare(struct certificate_table* table, char* name);
void certificate_table_clear(struct certificate_table* table);
#endif