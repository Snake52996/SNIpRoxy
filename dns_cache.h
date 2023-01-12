#ifndef SNIPROXY_DNS_CACHE_H_
#define SNIPROXY_DNS_CACHE_H_
#define _GNU_SOURCE
#include <baSe/list.h>
#include <ares.h>
#include <netdb.h>
#include <time.h>
struct dns_cache_entry{
    time_t valid_before;    // time before which current entry may be considered as valid
    char* hostname;         // DNS name
    uint16_t hostname_hash; // hash of hostname to accelerate lookup (string comparision)
    uint16_t flags;         // internal flags
    // start of entries from addrinfo
    int ai_family;
    int ai_flags;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr* ai_addr;
    // end of entries from addrinfo
};
struct dns_cache{
    List entries;           // list of entries, ordered by hash of entry
    size_t size_limit;      // maximum number of entries in list
    ListNode* next_replace; // the clock pointer for entry replacement
};
void dns_cache_init(struct dns_cache* cache, size_t cache_size);
struct dns_cache_entry* dns_cache_insert(
    struct dns_cache* cache,
    ListNode* hint, int hint_type, char* hostname, struct ares_addrinfo_node* address_node
);
bool dns_cache_lookup(struct dns_cache* cache, char* hostname, ListNode** hint, int* hint_type);
// make all dns entries invalid
void dns_cache_invalidate(struct dns_cache* cache);
// clear all cache, free memory allocated
void dns_cache_clear(struct dns_cache* cache);
#endif