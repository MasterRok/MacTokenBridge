// Thin PKCS#11 wrapper around the configured module, used by the helper.
// All functions return a CK_RV (0 == CKR_OK) or one of the P11_ERR_* codes below.
// Not thread-safe: the caller runs every call on one thread (see P11Thread.swift).

#ifndef MTB_P11_H
#define MTB_P11_H

#include <stddef.h>
#include <stdint.h>

#define P11_OK 0UL
#define P11_ERR_DLOPEN 0x80000001UL
#define P11_ERR_NO_FUNCTION_LIST 0x80000002UL
#define P11_ERR_NO_TOKEN 0x80000003UL
#define P11_ERR_NOT_FOUND 0x80000004UL
#define P11_ERR_BUFFER 0x80000005UL

#define P11_RV_USER_NOT_LOGGED_IN 0x101UL
#define P11_RV_USER_ALREADY_LOGGED_IN 0x100UL
#define P11_RV_PIN_INCORRECT 0xa0UL
#define P11_RV_PIN_LOCKED 0xa4UL

#define P11_CERTIFICATE_CATEGORY_AUTHORITY 2UL

unsigned long p11_load(const char *path);

/// Closes the session and finalizes the module, so the next p11_load starts from scratch
/// (needed after a cloud signing app such as SimplySign Desktop disconnects and reconnects).
void p11_finalize(void);

/// Opens (or replaces) the session on the first slot that has a token. A replaced session
/// is closed only after the new one is open, so the module keeps the user logged in.
unsigned long p11_open_session(void);
void p11_close_session(void);

/// Label and serial number of the token behind the current session, NUL-terminated.
unsigned long p11_token_info(char *label, size_t label_size, char *serial, size_t serial_size);

/// Copies the index-th certificate on the token: DER into der, CKA_ID into key_id, and
/// CKA_CERTIFICATE_CATEGORY into category (0 when the module does not report it).
/// Returns P11_ERR_NOT_FOUND once index is past the last certificate.
unsigned long p11_certificate_at(size_t index, uint8_t *der, size_t *der_len,
                                 uint8_t *key_id, size_t *key_id_len, unsigned long *category);

/// Sets *logged_in to 1 if the module already has the user logged in on the current session
/// (login state is per token, so it can survive reopening a session).
unsigned long p11_session_logged_in(int *logged_in);

unsigned long p11_login(const char *pin);

/// 1 if the private key needs a context-specific login before every signature.
unsigned long p11_key_always_authenticate(const uint8_t *key_id, size_t key_id_len, int *always);

/// CKM_RSA_PKCS signature over data (a DER DigestInfo). context_pin is used for
/// CKU_CONTEXT_SPECIFIC login when the key requires it, otherwise may be NULL.
unsigned long p11_sign_rsa_pkcs(const uint8_t *key_id, size_t key_id_len,
                                const uint8_t *data, size_t data_len,
                                const char *context_pin,
                                uint8_t *sig, size_t *sig_len);

#endif
