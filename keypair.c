#include "keypair.h"
#include <fcntl.h>
#include <unistd.h>
static void keypair_deleter_(void* target_){
    struct keypair* target = target_;
    free(target->hostname);
    gnutls_pcert_deinit(&target->cert);
    gnutls_privkey_deinit(target->key);
    free(target);
}
unsigned int keypair_key_hash(const void* key){
    unsigned int result = 0;
    const char* key_ = key;
    while(*key_ != '\0') result = (result << 2) + *(key_++);
    return result;
}
int keypair_key_compare(const void* lhs, const void* rhs){
    fprintf(stderr, "comparing [%s] and [%s] -> ", lhs, rhs);
    int result = strcmp((const char*)lhs, (const char*)rhs);
    fprintf(stderr, "%d\n", result);
    return result;
}
void certificate_table_init(struct certificate_table* table, size_t slots){
    HashTable_initialize(&table->table, slots, keypair_key_hash, strcmp);
}
static struct keypair* create_new_certificate(char* name){
    gnutls_x509_crq_t crq;
    gnutls_x509_privkey_t key;
    unsigned char buffer[10240];
    size_t buffer_size = sizeof(buffer);
    unsigned int bits;
    gnutls_x509_crq_init(&crq);
    gnutls_x509_privkey_init(&key);
    bits = gnutls_sec_param_to_pk_bits(GNUTLS_PK_ECC, GNUTLS_SEC_PARAM_ULTRA);
    gnutls_x509_privkey_generate(key, GNUTLS_PK_ECC, bits, 0);
    gnutls_x509_crq_set_version(crq, 1);
    gnutls_x509_crq_set_key(crq, key);
    gnutls_x509_crq_sign2(crq, key, GNUTLS_DIG_SHA384, 0);
    gnutls_x509_crq_export(crq, GNUTLS_X509_FMT_PEM, buffer, &buffer_size);
    gnutls_x509_crq_deinit(crq);
    FILE* request = fopen("request.pem", "w");
    fprintf(request, "%s", buffer);
    fclose(request);
    request = fopen("cert.cfg.template", "r");
    FILE* result = fopen("cert.cfg", "w");
    while(1){
        buffer_size = fread(buffer, 1, sizeof(buffer), request);
        fwrite(buffer, buffer_size, 1, result);
        if(buffer_size < sizeof(buffer)) break;
    }
    fprintf(result, "\ncn = \"%s\"\ndns_name = \"%s\"", name, name);
    fclose(request);
    fclose(result);
    pid_t pid = vfork();
    if(pid == -1){
        gnutls_x509_privkey_deinit(key);
        return NULL;
    }else if(pid == 0){
        close(STDOUT_FILENO);
        close(STDERR_FILENO);
        open("/dev/null", O_WRONLY);
        dup2(STDOUT_FILENO, STDERR_FILENO);
        execlp(
            "certtool", "certtool", "--generate-certificate", "--load-request", "request.pem",
            "--outfile", "result.pem", "--load-ca-certificate", "ca-cert.pem", "--load-ca-privkey",
            "ca-key.pem", "--template", "cert.cfg"
        );
    }else{
        int status;
        waitpid(pid, &status, 0);
        if(WIFEXITED(status) && WEXITSTATUS(status) == 0){
            struct keypair* kp_result = malloc(sizeof(struct keypair));
            RAII_set_deleter(kp_result, keypair_deleter_);
            kp_result->hostname = malloc(strlen(name) + 1);
            strcpy(kp_result->hostname, name);
            gnutls_datum_t datum;
            struct stat status;
            stat("result.pem", &status);
            datum.size = status.st_size;
            datum.data = malloc(datum.size);
            request = fopen("result.pem", "rb");
            fread(datum.data, datum.size, 1, request);
            fclose(request);
            gnutls_pcert_import_x509_raw(&kp_result->cert, &datum, GNUTLS_X509_FMT_PEM, 0);
            free(datum.data);
            gnutls_privkey_init(&kp_result->key);
            gnutls_privkey_import_x509(kp_result->key, key, GNUTLS_PRIVKEY_IMPORT_COPY);
            gnutls_x509_privkey_deinit(key);
            return kp_result;
        }else{
            gnutls_x509_privkey_deinit(key);
            return NULL;
        }
    }
}
struct keypair* certificate_table_prepare(struct certificate_table* table, char* name){
    struct keypair* kp_result = NULL;
    KeyValue* kv_result = HashTable_find(&table->table, name);
    if(kv_result == NULL){
        kp_result = create_new_certificate(name);
        HashTable_insert(&table->table, kp_result->hostname, false, kp_result, true, NULL);
        return kp_result;
    }
    else kp_result = kv_result->value;
    gnutls_x509_crt_t cert;
    gnutls_pcert_export_x509(&kp_result->cert, &cert);
    if(gnutls_x509_crt_get_expiration_time(cert) <= time(NULL)){
        if(atomic_load(&kp_result->references) == 0){
            HashTable_erase_entry_key_hint(&table->table, name, kv_result);
        }
        kp_result = create_new_certificate(name);
        HashTable_insert_direct(&table->table, kp_result->hostname, false, kp_result, true);
    }
    gnutls_x509_crt_deinit(cert);
    return kp_result;
}