#include "dns_cache.h"
#include <baSe/list.h>
#include <string.h>
enum HintType{
    HintTypeResult,     // result found
    HintTypeNext,       // record not found, emplace the new/refilled node before hint to get correct order
    HintTypeReplace,    // same hostname but timedout, simply replace with new record
};
static void convertToEntry(struct dns_cache_item* entry, const struct ares_addrinfo_node* address_node){
    entry->ai_addrlen = address_node->ai_addrlen;
    entry->ai_family = address_node->ai_family;
    entry->ai_flags = address_node->ai_flags;
    entry->ai_protocol = address_node->ai_protocol;
    entry->ai_socktype = address_node->ai_socktype;
    entry->ai_addr = malloc(entry->ai_addrlen);
    memcpy(entry->ai_addr, address_node->ai_addr, entry->ai_addrlen);
    struct dns_cache_timeout* timeout = entry->timeout_event->data;
    timeout->timeout_time = time(NULL) + address_node->ai_ttl;
}
static inline bool isTimeout(struct dns_cache_timeout* timeout){
    return timeout->timeout_time <= time(NULL);
}
static void insertTimeoutEvent(struct dns_cache* cache, ListNode* event_node){
    ListNode* after = NULL;
    struct dns_cache_timeout* reference_timeout = event_node->data;
    for(
        after = cache->timeout_events.head.prev;
        after != &(cache->timeout_events.head);
        after = after->prev
    ){
        struct dns_cache_timeout* timeout = after->data;
        if(timeout->timeout_time <= reference_timeout->timeout_time) break;
    }
    List_emplace_after(&cache->timeout_events, event_node, after);
}
static void insertEntry(struct dns_cache* cache, ListNode* entry_node){
    ListNode* before = NULL;
    struct dns_cache_item* reference_entry = entry_node->data;
    for(
        before = cache->timeout_events.head.next;
        before != &(cache->timeout_events.head);
        before = before->next
    ){
        struct dns_cache_item* entry = before->data;
        if(strcmp(reference_entry->hostname, entry->hostname) <= 0) break;
    }
    List_emplace_before(&cache->timeout_events, entry_node, before);
}
void dns_cache_init(struct dns_cache* cache, size_t cache_size){
    List_initialize(&cache->entries);
    List_initialize(&cache->timeout_events);
    cache->next_replace = &(cache->entries.head);
    cache->size_limit = cache_size;
}
struct dns_cache_item* dns_cache_insert(
    struct dns_cache* cache,
    ListNode* hint, int hint_type, char* hostname, struct ares_addrinfo_node* address_node
){
    if(hint != NULL && hint_type == HintTypeReplace){
        ListNode* timeout_event_node = ((struct dns_cache_item*)(hint->data))->timeout_event;
        convertToEntry(hint->data, address_node);
        List_detach(&cache->timeout_events, timeout_event_node);
        insertTimeoutEvent(cache, timeout_event_node);
        return hint->data;
    }
    struct dns_cache_item* target_item = NULL;
    struct dns_cache_timeout* target_timeout = NULL;
    ListNode* item_node = NULL;
    ListNode* timeout_node = NULL;
    if(cache->size_limit > List_size(&cache->entries)){
        target_item = malloc(sizeof(struct dns_cache_item));
        target_timeout = malloc(sizeof(struct dns_cache_timeout));
        item_node = ListNode_create(target_item, false);
        timeout_node = ListNode_create(target_timeout, false);
        target_item->timeout_event = timeout_node;
        target_timeout->target_item = item_node;
        List_emplace_back(&cache->entries, item_node);
        List_emplace_back(&cache->timeout_events, timeout_node);
    }else{
        for(;; cache->next_replace = cache->next_replace->next){
            if(cache->next_replace == &(cache->entries.head)) continue;
            struct dns_cache_item* target = cache->next_replace->data;
            if(isTimeout(target->timeout_event->data)) break;
            if(target->visited) target->visited = false;
            else break;
        }
        target_item = cache->next_replace->data;
        target_timeout = target_item->timeout_event->data;
        item_node = cache->next_replace;
        timeout_node = target_item->timeout_event;
        cache->next_replace = cache->next_replace->next;
    }
    target_item->visited = false;
    target_item->hostname = malloc(strlen(hostname) + 1);
    strcpy(target_item->hostname, hostname);
    convertToEntry(target_item, address_node);
    List_detach(&cache->entries, item_node);
    List_detach(&cache->timeout_events, timeout_node);
    if(hint != NULL && hint_type == HintTypeNext){
        List_emplace_before(&cache->entries, item_node, hint);
    }else{
        insertEntry(cache, item_node);
    }
    insertTimeoutEvent(cache, timeout_node);
    return target_item;
}
bool dns_cache_lookup(struct dns_cache* cache, char* hostname, ListNode** hint, int* hint_type){
    ListNode* node;
    struct dns_cache_item* entry;
    struct dns_cache_timeout* timeout;
    for(node = cache->entries.head.next; node != &cache->entries.head; node = node->next){
        entry = node->data;
        timeout = entry->timeout_event->data;
        int compare = strcmp(hostname, entry->hostname);
        if(compare == 0){
            if(hint != NULL) *hint = node;
            if(isTimeout(timeout)){
                if(hint_type != NULL) *hint_type = HintTypeReplace;
                return false;
            }else{
                if(hint_type != NULL) *hint_type = HintTypeResult;
                return true;
            }
        }else if(compare < 0){
            if(hint != NULL) *hint = node;
            if(hint_type != NULL) *hint_type = HintTypeNext;
            return false;
        }
    }
    if(hint != NULL) *hint = &cache->entries.head;
    if(hint_type != NULL) *hint_type = HintTypeNext;
    return false;
}