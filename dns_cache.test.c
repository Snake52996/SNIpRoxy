#include "dns_cache.h"
#include <arpa/inet.h>
#include <assert.h>
static char *hostnames[] = {"a.b.c", "d.e.f", "www.cache.test", "snake.moe"};

static char *ipv4_addr[] = {"1.2.3.4", "10.20.30.40", "254.254.254.254", "100.186.109.224"};
int main() {
  struct dns_cache cache;
  struct sockaddr_in address;
  struct dns_cache_entry *entry;
  ListNode *hint;
  int hint_type;
  bool return_value;
  dns_cache_init(&cache, 2);
  return_value = dns_cache_lookup(&cache, hostnames[0], NULL, NULL);
  assert(return_value == false);
  return_value = dns_cache_lookup(&cache, hostnames[0], &hint, &hint_type);
  assert(return_value == false);
  assert(hint == &cache.entries.head);
  struct ares_addrinfo_node node = {
      .ai_family = AF_INET,
      .ai_flags = 0,
      .ai_socktype = SOCK_STREAM,
      .ai_protocol = IPPROTO_TCP,
      .ai_addrlen = sizeof(address),
      .ai_addr = (struct sockaddr *)&address,
      .ai_next = NULL,
  };
  address.sin_family = AF_INET;
  address.sin_port = htons(443);
  inet_pton(AF_INET, ipv4_addr[0], &address.sin_addr);
  node.ai_ttl = 60000;
  entry = dns_cache_insert(&cache, NULL, 0, hostnames[0], &node);
  return_value = dns_cache_lookup(&cache, hostnames[0], &hint, &hint_type);
  assert(return_value == true);
  assert(hint->data == entry);
  inet_pton(AF_INET, ipv4_addr[1], &address.sin_addr);
  entry = dns_cache_insert(&cache, NULL, 0, hostnames[1], &node);
  return_value = dns_cache_lookup(&cache, hostnames[1], NULL, NULL);
  assert(return_value == true);
  return_value = dns_cache_lookup(&cache, hostnames[1], &hint, &hint_type);
  assert(hint->data == entry);
  return_value = dns_cache_lookup(&cache, hostnames[2], &hint, &hint_type);
  assert(return_value == false);
  inet_pton(AF_INET, ipv4_addr[2], &address.sin_addr);
  hint = cache.entries.head.next->next;
  ((struct dns_cache_entry *)(hint->prev->data))->flags = -1;
  ((struct dns_cache_entry *)(hint->data))->flags = 0;
  cache.next_replace = hint;
  entry = dns_cache_insert(&cache, hint, hint_type, hostnames[2], &node);
  return_value = dns_cache_lookup(&cache, hostnames[0], NULL, NULL) &&
                 dns_cache_lookup(&cache, hostnames[1], NULL, NULL);
  assert(return_value == false);
  return_value = dns_cache_lookup(&cache, hostnames[2], &hint, &hint_type);
  assert(return_value == true);
  assert(hint->data == entry);
  inet_pton(AF_INET, ipv4_addr[3], &address.sin_addr);
  node.ai_ttl = 0;
  entry = dns_cache_insert(&cache, NULL, 0, hostnames[2], &node);
  return_value = dns_cache_lookup(&cache, hostnames[2], &hint, &hint_type);
  assert(return_value == false);
  assert(hint->data == entry);
  entry = dns_cache_insert(&cache, hint, hint_type, hostnames[2], &node);
  dns_cache_clear(&cache);
  return 0;
}