#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "bhpkg.h"

#define CHUNK_SIZE 131072

bool
crypto_hash_file (const char *filepath, char *out_hex)
{
  int fd;
  EVP_MD_CTX *mdctx;
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned char *buf;
  unsigned int md_len;
  ssize_t bytes_read;

  out_hex[0] = '\0';

  fd = open (filepath, O_RDONLY | O_CLOEXEC | O_NOATIME);
  if (fd < 0 && errno == EPERM)
    fd = open (filepath, O_RDONLY | O_CLOEXEC);

  if (fd < 0)
    return false;

#if defined(POSIX_FADV_SEQUENTIAL)
  posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

  buf = xmalloc (CHUNK_SIZE);
  mdctx = EVP_MD_CTX_new ();

  if (LIKELY (mdctx))
    {
      if (EVP_DigestInit_ex (mdctx, EVP_sha256 (), NULL) == 1)
        {
          while ((bytes_read = read (fd, buf, CHUNK_SIZE)) > 0)
            {
              if (EVP_DigestUpdate (mdctx, buf, bytes_read) != 1)
                break;
            }

          if (bytes_read == 0 && EVP_DigestFinal_ex (mdctx, hash, &md_len) == 1)
            {
              for (unsigned int i = 0; i < md_len; i++)
                sprintf (out_hex + (i * 2), "%02x", hash[i]);
              out_hex[64] = '\0';
            }
        }
      EVP_MD_CTX_free (mdctx);
    }

  free (buf);
  close (fd);
  return (out_hex[0] != '\0');
}

bool
crypto_verify_sha256 (const char *filepath, const char *expected_hash)
{
  char hex_hash[65] = { 0 };

  if (!filepath || !expected_hash)
    return false;

  if (!crypto_hash_file (filepath, hex_hash))
    {
      print_err ("Crypto: Failed to hash file: %s", filepath);
      return false;
    }

  return (strcmp (hex_hash, expected_hash) == 0);
}

bool
crypto_verify_signature (const char *filepath, const char *sigpath, const char *pubkey_path)
{
  FILE *keyfile, *sigfile;
  EVP_PKEY *pubkey;
  unsigned char sig[4096];
  size_t sig_len;
  EVP_MD_CTX *mdctx;
  int fd;
  unsigned char *buf;
  ssize_t bytes_read;
  int result = 0;

  keyfile = fopen (pubkey_path, "re");
  if (!keyfile)
    {
      print_err ("Crypto: Public key not found at %s", pubkey_path);
      return false;
    }

  pubkey = PEM_read_PUBKEY (keyfile, NULL, NULL, NULL);
  fclose (keyfile);
  if (!pubkey)
    {
      print_err ("Crypto: Failed to parse RSA public key.");
      return false;
    }

  sigfile = fopen (sigpath, "rbe");
  if (!sigfile)
    {
      print_err ("Crypto: Signature file missing: %s", sigpath);
      EVP_PKEY_free (pubkey);
      return false;
    }

  sig_len = fread (sig, 1, sizeof (sig), sigfile);
  fclose (sigfile);

  mdctx = EVP_MD_CTX_new ();
  if (!mdctx)
    {
      EVP_PKEY_free (pubkey);
      return false;
    }

  if (EVP_DigestVerifyInit (mdctx, NULL, EVP_sha256 (), NULL, pubkey) <= 0)
    goto sig_cleanup;

  fd = open (filepath, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    goto sig_cleanup;

#if defined(POSIX_FADV_SEQUENTIAL)
  posix_fadvise (fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif

  buf = xmalloc (CHUNK_SIZE);
  while ((bytes_read = read (fd, buf, CHUNK_SIZE)) > 0)
    {
      if (EVP_DigestVerifyUpdate (mdctx, buf, bytes_read) <= 0)
        break;
    }

  if (bytes_read == 0)
    result = EVP_DigestVerifyFinal (mdctx, sig, sig_len);

  free (buf);
  close (fd);

sig_cleanup:
  EVP_MD_CTX_free (mdctx);
  EVP_PKEY_free (pubkey);

  if (result != 1)
    {
      print_err ("Crypto: Signature verification failed unconditionally.");
      return false;
    }

  return true;
}