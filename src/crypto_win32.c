/*
** SQLCipher
** http://sqlcipher.net
**
** Copyright (c) 2008 - 2022, ZETETIC LLC
** All rights reserved.
**
** Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are met:
**     * Redistributions of source code must retain the above copyright
**       notice, this list of conditions and the following disclaimer.
**     * Redistributions in binary form must reproduce the above copyright
**       notice, this list of conditions and the following disclaimer in the
**       documentation and/or other materials provided with the distribution.
**     * Neither the name of the ZETETIC LLC nor the
**       names of its contributors may be used to endorse or promote products
**       derived from this software without specific prior written permission.
**
** THIS SOFTWARE IS PROVIDED BY ZETETIC LLC ''AS IS'' AND ANY
** EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
** WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
** DISCLAIMED. IN NO EVENT SHALL ZETETIC LLC BE LIABLE FOR ANY
** DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
** (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
** LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
** ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
** SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
**
*/
/* BEGIN SQLCIPHER */
#ifdef SQLITE_HAS_CODEC
#ifdef SQLCIPHER_CRYPTO_WIN32

#include "crypto.h"
#include "sqlcipher.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#undef WIN32_LEAN_AND_MEAN
#undef NOMINMAX

#include <bcrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "bcrypt.lib")
#endif

static int sqlcipher_win32_get_key_sz(void *ctx) {
  /* AES-256 always uses a 256-bit (32 byte) key. */
  return 32;
}

static int sqlcipher_win32_get_iv_sz(void *ctx) {
  /* AES CBC always uses a 128 bit (16 byte) IV. */
  return 16;
}

static int sqlcipher_win32_get_block_sz(void *ctx) {
  /* AES always uses 128 bit (16 byte) blocks. */
  return 16;
}

static int sqlcipher_win32_random(void *ctx, void *buffer, int length) {
  NTSTATUS status = BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
  return BCRYPT_SUCCESS(status) ? SQLITE_OK : SQLITE_ERROR;
}

static int sqlcipher_win32_add_random(void *ctx, void *buffer, int length) {
  return SQLITE_OK;
}

static int sqlcipher_win32_get_hmac_sz(void *ctx, int algorithm) {
  switch(algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      /* SHA1 is 160 bits (20 bytes) */
      return 20;
    case SQLCIPHER_HMAC_SHA256:
      /* SHA256 is 256 bits (32 bytes) */
      return 32;
    case SQLCIPHER_HMAC_SHA512:
      /* SHA512 is 512 bits (64 bytes) */
      return 64;
    default:
      assert(0 && "Unknown hmac algorithm");
      return 0;
  }
}

static int sqlcipher_win32_hmac(void *ctx, int algorithm, unsigned char *hmac_key, int key_sz, unsigned char *in, int in_sz, unsigned char *in2, int in2_sz, unsigned char *out) {
  int rc = SQLITE_OK;
  NTSTATUS status = -1;
  LPCWSTR pszAlgId = NULL;
  BCRYPT_ALG_HANDLE hAlg = NULL;
  BCRYPT_HASH_HANDLE hHash = NULL;
  DWORD dwUnused = 0;
  DWORD dwHmacCtxLen = 0;
  PBYTE pbHmacCtx = NULL;
  DWORD dwOutSize = 0;

  switch (algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      pszAlgId = BCRYPT_SHA1_ALGORITHM;
      break;
    case SQLCIPHER_HMAC_SHA256:
      pszAlgId = BCRYPT_SHA256_ALGORITHM;
      break;
    case SQLCIPHER_HMAC_SHA512:
      pszAlgId = BCRYPT_SHA512_ALGORITHM;
      break;
    default:
      assert(0 && "Unknown HMAC algorithm");
      goto error;
  }
  dwOutSize = sqlcipher_win32_get_hmac_sz(NULL, algorithm);
  assert(dwOutSize != 0);

  status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptOpenAlgorithmProvider returned %d", (int)status);
    goto error;
  }

  status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwHmacCtxLen, sizeof(DWORD), &dwUnused, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, ...) returned %x", (int)status);
    goto error;
  }

  pbHmacCtx = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwHmacCtxLen);
  if (pbHmacCtx == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: failed to allocate %d bytes", (int)dwHmacCtxLen);
    goto error;
  }

  status = BCryptCreateHash(hAlg, &hHash, pbHmacCtx, dwHmacCtxLen, hmac_key, key_sz, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptCreateHash returned %d", (int)status);
    goto error;
  }
  status = BCryptHashData(hHash, (PBYTE)in, in_sz, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptHashData returned %d", (int)status);
    goto error;
  }
  if (in2 != NULL) {
    status = BCryptHashData(hHash, (PBYTE)in2, in2_sz, 0);
    if (!BCRYPT_SUCCESS(status)) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptHashData returned %d", (int)status);
      goto error;
    }
  }

  status = BCryptFinishHash(hHash, out, dwOutSize, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_hmac: BCryptFinishHash returned %d", (int)status);
    goto error;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if (hHash != NULL && hHash != INVALID_HANDLE_VALUE) {
    status = BCryptDestroyHash(hHash);
    assert(BCRYPT_SUCCESS(status));
  }
  if (pbHmacCtx != NULL) {
    HeapFree(GetProcessHeap(), 0, pbHmacCtx);
  }
  if (hAlg != NULL && hAlg != INVALID_HANDLE_VALUE) {
    status = BCryptCloseAlgorithmProvider(hAlg, 0);
    assert(BCRYPT_SUCCESS(status));
  }
  return rc;
}

static int sqlcipher_win32_kdf(void *ctx, int algorithm, const unsigned char *pass, int pass_sz, unsigned char* salt, int salt_sz, int workfactor, int key_sz, unsigned char *key) {
  int rc = SQLITE_OK;
  NTSTATUS status = -1;
  BCRYPT_ALG_HANDLE hAlg = NULL;
  LPCWSTR pszAlgId = NULL;

  switch (algorithm) {
    case SQLCIPHER_HMAC_SHA1:
      pszAlgId = BCRYPT_SHA1_ALGORITHM;
      break;
    case SQLCIPHER_HMAC_SHA256:
      pszAlgId = BCRYPT_SHA256_ALGORITHM;
      break;
    case SQLCIPHER_HMAC_SHA512:
      pszAlgId = BCRYPT_SHA512_ALGORITHM;
      break;
    default:
      assert(0 && "Unknown HMAC algorithm");
      goto error;
  }

  status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_kdf: BCryptOpenAlgorithmProvider returned %d", (int)status);
    goto error;
  }

  status = BCryptDeriveKeyPBKDF2(hAlg, (PUCHAR)pass, pass_sz, (PUCHAR)salt, salt_sz, workfactor, key, key_sz, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_kdf: BCryptDeriveKeyPBKDF2 returned %d", (int)status);
    goto error;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if (hAlg != NULL && hAlg != INVALID_HANDLE_VALUE) {
    status = BCryptCloseAlgorithmProvider(hAlg, 0);
    assert(BCRYPT_SUCCESS(status));
  }
  return rc;
}

static int sqlcipher_win32_cipher(void *ctx, int mode, unsigned char *key, int key_sz, unsigned char *iv, unsigned char *in, int in_sz, unsigned char *out) {
  BCRYPT_ALG_HANDLE hAesAlg = NULL;
  BCRYPT_KEY_HANDLE hKey = NULL;
  NTSTATUS status = -1;
  DWORD dwUnused = 0;
  DWORD dwKeyObjectLen = 0;
  DWORD dwIvLen = 0;
  PBYTE pbKeyObject = NULL;
  PBYTE pbIV = NULL;
  DWORD dwOutLen = 0;
  int rc = SQLITE_OK;

  status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptOpenAlgorithmProvider returned %d", (int)status);
    goto error;
  }

  status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, ...) returned %d", (int)status);
    goto error;
  }

  status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&dwKeyObjectLen, sizeof(DWORD), &dwUnused, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, ...) returned %d", (int)status);
    goto error;
  }

  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwKeyObjectLen);
  if (pbKeyObject == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: failed to allocate %d bytes", (int)dwKeyObjectLen);
    goto error;
  }

  status = BCryptGenerateSymmetricKey(hAesAlg, &hKey, pbKeyObject, dwKeyObjectLen, (PBYTE)key, key_sz, 0);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptGenerateSymmetricKey returned %d", (int)status);
    goto error;
  }

  dwIvLen = sqlcipher_win32_get_iv_sz(NULL);
  assert(dwIvLen == sqlcipher_win32_get_block_sz(NULL));
  /* bcrypt scribbles all over the IV, so copy it. */
  pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, dwIvLen);
  if (pbIV == NULL) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: failed to allocate %d bytes", (int)dwIvLen);
    goto error;
  }
  memcpy((void*)pbIV, (const void*)iv, dwIvLen);

  if (mode == CIPHER_ENCRYPT) {
    status = BCryptEncrypt(
      hKey,
      in,
      in_sz,
      NULL,
      pbIV,
      dwIvLen,
      out,
      in_sz,
      &dwOutLen,
      0
    );
    if (!BCRYPT_SUCCESS(status)) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptDecrypt returned %d", (int)status);
      goto error;
    }
  } else {
    assert(mode == CIPHER_DECRYPT);
    status = BCryptDecrypt(
      hKey,
      in,
      in_sz,
      NULL,
      pbIV,
      dwIvLen,
      out,
      in_sz,
      &dwOutLen,
      0
    );
    if (!BCRYPT_SUCCESS(status)) {
      sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptDecrypt returned %d", (int)status);
      goto error;
    }
  }
  if (dwOutLen != in_sz) {
    sqlcipher_log(
      SQLCIPHER_LOG_ERROR,
      "sqlcipher_win32_cipher: bcrypt output (when %s) is wrong length: got %d, need %d",
      mode == CIPHER_ENCRYPT ? "encrypting" : "decrypting",
      (int)dwOutLen, (int)in_sz
    );
    goto error;
  }

  goto cleanup;
error:
  rc = SQLITE_ERROR;
cleanup:
  if (hKey != NULL && hKey != INVALID_HANDLE_VALUE) {
    status = BCryptDestroyKey(hKey);
    assert(BCRYPT_SUCCESS(status));
  }
  if (pbIV != NULL) {
    HeapFree(GetProcessHeap(), 0, pbIV);
  }
  if (pbKeyObject != NULL) {
    HeapFree(GetProcessHeap(), 0, pbKeyObject);
  }
  if (hAesAlg != NULL && hAesAlg != INVALID_HANDLE_VALUE) {
    status = BCryptCloseAlgorithmProvider(hAesAlg, 0);
    assert(BCRYPT_SUCCESS(status));
  }
  return rc;
}

static const char* sqlcipher_win32_get_provider_name(void *ctx) {
  return "win32";
}

static const char* sqlcipher_win32_get_provider_version(void *ctx) {
  return "unknown";
}

static const char* sqlcipher_win32_get_cipher(void *ctx) {
  return "aes-256-cbc";
}

static int sqlcipher_win32_ctx_init(void **ctx) {
  return SQLITE_OK;
}

static int sqlcipher_win32_ctx_free(void **ctx) {
  return SQLITE_OK;
}

static int sqlcipher_win32_fips_status(void *ctx) {
  sqlcipher_log(SQLCIPHER_LOG_INFO, "sqlcipher_win32_cipher: BCryptGetFipsAlgorithmMode fips_status");
  BOOLEAN pfEnabled = 0;
  NTSTATUS status = BCryptGetFipsAlgorithmMode(&pfEnabled);
  if (!BCRYPT_SUCCESS(status)) {
    sqlcipher_log(SQLCIPHER_LOG_ERROR, "sqlcipher_win32_cipher: BCryptGetFipsAlgorithmMode returned %d", (int)status);
    return SQLITE_ERROR;
  }
  return (int)pfEnabled;
}

int sqlcipher_win32_setup(sqlcipher_provider *p) {
  p->get_provider_name = sqlcipher_win32_get_provider_name;
  p->random = sqlcipher_win32_random;
  p->hmac = sqlcipher_win32_hmac;
  p->kdf = sqlcipher_win32_kdf;
  p->cipher = sqlcipher_win32_cipher;
  p->get_cipher = sqlcipher_win32_get_cipher;
  p->get_key_sz = sqlcipher_win32_get_key_sz;
  p->get_iv_sz = sqlcipher_win32_get_iv_sz;
  p->get_block_sz = sqlcipher_win32_get_block_sz;
  p->get_hmac_sz = sqlcipher_win32_get_hmac_sz;
  p->ctx_init = sqlcipher_win32_ctx_init;
  p->ctx_free = sqlcipher_win32_ctx_free;
  p->add_random = sqlcipher_win32_add_random;
  p->fips_status = sqlcipher_win32_fips_status;
  p->get_provider_version = sqlcipher_win32_get_provider_version;
  return SQLITE_OK;
}

#endif /* SQLCIPHER_CRYPTO_WIN32 */
#endif /* SQLITE_HAS_CODEC */

/* END SQLCIPHER */
