#ifndef SNIPROXY_DNS_CACHE_HH_
#define SNIPROXY_DNS_CACHE_HH_
#include <functional>
#include <mutex>
#include <unordered_map>
#include <utility>
template <typename Key, std::move_constructible Value, size_t MaxEntries> class Cache {
private:
  std::recursive_mutex                                mutex;
  std::unordered_map<Key, std::pair<Value, uint32_t>> storage;

  // remove a entry from storage
  void kick_out() {
    auto iterator = this->storage.end();
    for (auto iter = this->storage.begin(); iter != this->storage.end(); iter++) {
      if (iterator == this->storage.end() || iter->second.second < iterator->second.second) {
        iterator = iter;
      }
    }
    this->storage.erase(iterator);
  }

public:
  // checks if the entry is actually valid: entries in the cache on which the checker returns false will be
  // treated as invalid and may be erased/replaced
  using checker_t = std::function<bool(const Value &value)>;

  // if the required key does not exist in the cache or is treated as invalid, use build to build a new entry
  using entry_builder_t = std::function<Value()>;

  // get a value associated with specified key from the cache
  Value *get(const Key &key, const checker_t &checker, bool age = true) {
    std::lock_guard lock(this->mutex);

    // try to find an entry
    auto iterator = this->storage.find(key);
    if (iterator != this->storage.cend() && checker(iterator->second.first) == false) {
      // if an entry is found but decided as invalid, erase it
      this->storage.erase(iterator);
      iterator = this->storage.end();
    }
    // aging algorithm for cache management
    if (age) {
      for (auto iter = this->storage.begin(); iter != this->storage.end(); iter++) {
        if (iter != iterator) {
          iter->second.second >>= 1;
        } else {
          iter->second.second = 0x80000000u | (iter->second.second >> 1);
        }
      }
    }
    if (iterator == this->storage.cend()) {
      // either the value does not exist at all, or it failed the check and is erased just now
      return nullptr;
    }
    return &iterator->second.first;
  }

  // get a value associated with specified key from the cache
  //  if the value does not exist or failed the check by checker, build a new one with builder and return it
  Value &get(const Key &key, const checker_t &checker, const entry_builder_t &builder, bool age = true) {
    std::lock_guard lock(this->mutex);

    auto result = this->get(key, checker, age);

    if (result != nullptr) {
      return *result;
    }
    // if no entry is found given the key, build one using the builder
    if (this->storage.size() == MaxEntries) {
      // but remove a old one first if we are reaching storage limit
      this->kick_out();
    }
    // try_emplace is employed just for its clearer signature
    return this->storage.try_emplace(key, std::move(builder()), 0x80000000u).first->second.first;
  }

  // set value directly
  //  if a value associated with the specified key already exists, it will be erased
  Value &set(const Key &key, Value &&value) {
    std::lock_guard lock(this->mutex);
    return this->get(
      key, [](const Value &value) { return false; }, [&value]() { return std::move(value); }, false
    );
  }

  // clear whole cache
  void clear() {
    std::lock_guard lock(this->mutex);
    this->storage.clear();
  }
};
#endif