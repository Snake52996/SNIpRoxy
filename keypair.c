#include "keypair.h"
#include "ca.h"
#include <fcntl.h>
#include <unistd.h>
static void keypair_deleter_(void *target_) {
  struct keypair *target = target_;
  free(target->hostname);
  gnutls_pcert_deinit(&target->cert);
  gnutls_privkey_deinit(target->key);
  free(target);
}
unsigned int keypair_key_hash(const void *key) {
  unsigned int result = 0;
  const char *key_ = key;
  while (*key_ != '\0')
    result = (result << 2) + *(key_++);
  return result;
}
void certificate_table_init(struct certificate_table *table, size_t slots) {
  HashTable_initialize(&table->table, slots, keypair_key_hash, (int (*)(const void *, const void *))strcmp);
}
static struct keypair *create_new_certificate(char *name) {
  gnutls_x509_crt_t cert;
  gnutls_x509_privkey_t key;
  struct keypair *kp_result = malloc(sizeof(struct keypair));
  RAII_set_deleter(kp_result, keypair_deleter_);
  kp_result->hostname = malloc(strlen(name) + 1);
  strcpy(kp_result->hostname, name);
  generate_certificate(name, &cert, &key);
  gnutls_pcert_import_x509(&kp_result->cert, cert, 0);
  gnutls_privkey_init(&kp_result->key);
  gnutls_privkey_import_x509(kp_result->key, key, GNUTLS_PRIVKEY_IMPORT_COPY);
  gnutls_x509_crt_deinit(cert);
  gnutls_x509_privkey_deinit(key);
  return kp_result;
}
struct keypair *certificate_table_prepare(struct certificate_table *table, char *name) {
  struct keypair *kp_result = NULL;
  KeyValue *kv_result = HashTable_find(&table->table, name);
  if (kv_result == NULL) {
    kp_result = create_new_certificate(name);
    HashTable_insert(&table->table, kp_result->hostname, false, kp_result, true, NULL);
    return kp_result;
  } else
    kp_result = kv_result->value;
  gnutls_x509_crt_t cert;
  gnutls_pcert_export_x509(&kp_result->cert, &cert);
  if (gnutls_x509_crt_get_expiration_time(cert) <= time(NULL)) {
    if (atomic_load(&kp_result->references) == 0) {
      HashTable_erase_entry_key_hint(&table->table, name, kv_result);
    }
    kp_result = create_new_certificate(name);
    HashTable_insert_direct(&table->table, kp_result->hostname, false, kp_result, true);
  }
  gnutls_x509_crt_deinit(cert);
  return kp_result;
}
void certificate_table_clear(struct certificate_table *table) { HashTable_clear(&table->table); }