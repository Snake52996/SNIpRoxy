#include "dns_cache.h"
#include <baSe/list.h>
#include <string.h>
enum HintType {
  HintTypeResult,  // result found
  HintTypeNext,    // record not found, emplace the new/refilled node before hint to get correct order
  HintTypeReplace, // same hostname but timedout, simply replace with new record
};
enum DNSEntryFlags {
  DNSEntryFlagVisited = 1,
};
static inline uint16_t calculate_hash(const char *hostname) {
  uint16_t result = 0xd00b;
  while (*hostname != '\0')
    result = (result + *hostname++) << 1;
  return result;
}
static struct dns_cache_entry *allocate_dns_cache_entry() {
  struct dns_cache_entry *entry = malloc(sizeof(struct dns_cache_entry));
  // just initialize critical fields
  entry->ai_addr = NULL;
  entry->flags = 0;
  entry->hostname = NULL;
  entry->valid_before = 0;
  return entry;
}
static void fill_addrinfo(struct dns_cache_entry *entry, const struct ares_addrinfo_node *address_node) {
  entry->ai_addrlen = address_node->ai_addrlen;
  entry->ai_family = address_node->ai_family;
  entry->ai_flags = address_node->ai_flags;
  entry->ai_protocol = address_node->ai_protocol;
  entry->ai_socktype = address_node->ai_socktype;
  if (entry->ai_addr != NULL)
    free(entry->ai_addr);
  entry->ai_addr = malloc(entry->ai_addrlen);
  memcpy(entry->ai_addr, address_node->ai_addr, entry->ai_addrlen);
  entry->valid_before = time(NULL) + address_node->ai_ttl;
}
static void fill_hostname(struct dns_cache_entry *entry, const char *hostname) {
  if (entry->hostname != NULL)
    free(entry->hostname);
  entry->hostname = malloc(strlen(hostname) + 1);
  strcpy(entry->hostname, hostname);
  entry->hostname_hash = calculate_hash(entry->hostname);
}
static inline bool is_cache_timeout(const struct dns_cache_entry *entry) {
  return entry->valid_before <= time(NULL);
}
static void insert_entry(struct dns_cache *cache, ListNode *entry_node) {
  ListNode *before = NULL;
  struct dns_cache_entry *reference_entry = entry_node->data;
  for (before = cache->entries.head.next; before != &(cache->entries.head); before = before->next) {
    struct dns_cache_entry *entry = before->data;
    if (entry->hostname_hash >= reference_entry->hostname_hash)
      break;
  }
  List_emplace_before(&cache->entries, entry_node, before);
}
static void rotate_next_replace(struct dns_cache *cache) {
  while (true) {
    if (cache->next_replace != &(cache->entries.head)) {
      struct dns_cache_entry *target = cache->next_replace->data;
      if (is_cache_timeout(target))
        break;
      if (target->flags & DNSEntryFlagVisited) {
        target->flags &= ~DNSEntryFlagVisited;
      } else {
        break;
      }
    }
    cache->next_replace = cache->next_replace->next;
  }
}
void dns_cache_init(struct dns_cache *cache, size_t cache_size) {
  List_initialize(&cache->entries);
  cache->next_replace = &(cache->entries.head);
  cache->size_limit = cache_size;
}
struct dns_cache_entry *dns_cache_insert(
    struct dns_cache *cache, ListNode *hint, int hint_type, char *hostname,
    struct ares_addrinfo_node *address_node
) {
  if (hint != NULL && hint_type == HintTypeReplace) {
    fill_addrinfo(hint->data, address_node);
    return hint->data;
  }
  struct dns_cache_entry *target_item = NULL;
  ListNode *item_node = NULL;
  if (cache->size_limit > List_size(&cache->entries)) {
    target_item = allocate_dns_cache_entry();
    item_node = ListNode_create(target_item, false);
  } else {
    rotate_next_replace(cache);
    item_node = cache->next_replace;
    target_item = item_node->data;
    cache->next_replace = cache->next_replace->next;
    if (hint != NULL && hint_type == HintTypeNext) {
      if (hint == item_node)
        hint = hint->next;
    }
    List_detach(&cache->entries, item_node);
  }
  target_item->flags = 0;
  fill_hostname(target_item, hostname);
  fill_addrinfo(target_item, address_node);
  if (hint != NULL && hint_type == HintTypeNext) {
    List_emplace_before(&cache->entries, item_node, hint);
  } else {
    insert_entry(cache, item_node);
  }
  return target_item;
}
bool dns_cache_lookup(struct dns_cache *cache, char *hostname, ListNode **hint, int *hint_type) {
  ListNode *node;
  struct dns_cache_entry *entry;
  uint16_t hash = calculate_hash(hostname);
  for (node = cache->entries.head.next; node != &cache->entries.head; node = node->next) {
    entry = node->data;
    if (entry->hostname_hash == hash) {
      if (strcmp(entry->hostname, hostname) != 0)
        continue;
      if (hint != NULL)
        *hint = node;
      if (is_cache_timeout(entry)) {
        if (hint_type != NULL)
          *hint_type = HintTypeReplace;
        return false;
      } else {
        entry->flags |= DNSEntryFlagVisited;
        if (hint_type != NULL)
          *hint_type = HintTypeResult;
        return true;
      }
    } else if (entry->hostname_hash > hash) {
      break;
    }
  }
  if (hint != NULL)
    *hint = node;
  if (hint_type != NULL)
    *hint_type = HintTypeNext;
  return false;
}
void dns_cache_invalidate(struct dns_cache *cache) {
  for (ListNode *node = cache->entries.head.next; node != &(cache->entries.head); node = node->next) {
    ((struct dns_cache_entry *)(node->data))->valid_before = 0;
  }
}
void dns_cache_clear(struct dns_cache *cache) {
  while (!List_empty(&cache->entries)) {
    ListNode *node = cache->entries.head.next;
    struct dns_cache_entry *entry = node->data;
    if (entry->ai_addr != NULL)
      free(entry->ai_addr);
    if (entry->hostname != NULL)
      free(entry->hostname);
    free(entry);
    List_erase(&cache->entries, node);
  }
}