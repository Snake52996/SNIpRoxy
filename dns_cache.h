#ifndef SNIPROXY_DNS_CACHE_H_
#define SNIPROXY_DNS_CACHE_H_
#define _GNU_SOURCE
#include <baSe/hashtable.h>
#include <ares.h>
#include <netdb.h>
#include <time.h>
struct dns_cache_item{
    char* hostname;
    int ai_family;
    int ai_flags;
    int ai_socktype;
    int ai_protocol;
    socklen_t ai_addrlen;
    struct sockaddr* ai_addr;
    ListNode* timeout_event;
    bool visited;
};
struct dns_cache_timeout{
    time_t timeout_time;
    ListNode* target_item;
};
struct dns_cache{
    List entries;
    List timeout_events;
    size_t size_limit;
    ListNode* next_replace;
};
void dns_cache_init(struct dns_cache* cache, size_t cache_size);
struct dns_cache_item* dns_cache_insert(
    struct dns_cache* cache,
    ListNode* hint, int hint_type, char* hostname, struct ares_addrinfo_node* address_node
);
bool dns_cache_lookup(struct dns_cache* cache, char* hostname, ListNode** hint, int* hint_type);
#endif