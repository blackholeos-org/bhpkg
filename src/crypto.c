#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "bhpkg.h"

bool crypto_verify_sha256(const char *filepath, const char *expected_hash) {
    if (!filepath || !expected_hash) return false;

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) {
        print_err("Crypto: Failed to open file for hashing: %s", filepath);
        return false;
    }

    struct stat sb;
    if (fstat(fd, &sb) < 0 || sb.st_size == 0) {
        close(fd);
        return false;
    }

    void *mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) {
        print_err("Crypto: Failed to mmap file for hashing.");
        close(fd);
        return false;
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) goto cleanup_map;

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) goto cleanup_ctx;
    if (EVP_DigestUpdate(mdctx, mapped, sb.st_size) != 1) goto cleanup_ctx;

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    if (EVP_DigestFinal_ex(mdctx, hash, &md_len) != 1) goto cleanup_ctx;

    EVP_MD_CTX_free(mdctx);
    munmap(mapped, sb.st_size);
    close(fd);

    char hex_hash[65];
    for (unsigned int i = 0; i < md_len; i++) {
        sprintf(hex_hash + (i * 2), "%02x", hash[i]);
    }
    hex_hash[64] = '\0';

    return (strcmp(hex_hash, expected_hash) == 0);

cleanup_ctx:
    EVP_MD_CTX_free(mdctx);
cleanup_map:
    munmap(mapped, sb.st_size);
    close(fd);
    return false;
}

bool crypto_verify_signature(const char *filepath, const char *sigpath, const char *pubkey_path) {
    FILE *keyfile = fopen(pubkey_path, "r");
    if (!keyfile) {
        print_err("Crypto: Public key not found at %s", pubkey_path);
        return false; 
    }
    
    EVP_PKEY *pubkey = PEM_read_PUBKEY(keyfile, NULL, NULL, NULL);
    fclose(keyfile);
    if (!pubkey) {
        print_err("Crypto: Failed to parse RSA public key.");
        return false;
    }

    FILE *sigfile = fopen(sigpath, "rb");
    if (!sigfile) { 
        print_err("Crypto: Signature file missing: %s", sigpath);
        EVP_PKEY_free(pubkey); 
        return false; 
    }
    
    unsigned char sig[4096];
    size_t sig_len = fread(sig, 1, sizeof(sig), sigfile);
    fclose(sigfile);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pubkey); return false; }

    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pubkey) <= 0) {
        goto sig_fail;
    }

    int fd = open(filepath, O_RDONLY);
    if (fd < 0) goto sig_fail;

    struct stat sb; 
    if (fstat(fd, &sb) < 0) { close(fd); goto sig_fail; }

    void *mapped = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mapped == MAP_FAILED) { close(fd); goto sig_fail; }

    if (EVP_DigestVerifyUpdate(mdctx, mapped, sb.st_size) <= 0) {
        munmap(mapped, sb.st_size); close(fd); goto sig_fail;
    }

    munmap(mapped, sb.st_size);
    close(fd);

    int result = EVP_DigestVerifyFinal(mdctx, sig, sig_len);
    EVP_MD_CTX_free(mdctx); 
    EVP_PKEY_free(pubkey);
    return (result == 1);

sig_fail:
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pubkey);
    print_err("Crypto: Signature verification failed unconditionally.");
    return false;
}