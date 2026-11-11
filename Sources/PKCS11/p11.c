#include "p11.h"

#include <dlfcn.h>
#include <string.h>

#include "pkcs11.h"

static CK_FUNCTION_LIST_PTR fl = NULL;
static CK_SESSION_HANDLE session = CK_INVALID_HANDLE;

unsigned long p11_load(const char *path) {
	if (fl) {
		return CKR_OK;
	}
	void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!lib) {
		return P11_ERR_DLOPEN;
	}
	CK_C_GetFunctionList get_function_list = (CK_C_GetFunctionList)dlsym(lib, "C_GetFunctionList");
	if (!get_function_list) {
		return P11_ERR_NO_FUNCTION_LIST;
	}
	CK_FUNCTION_LIST_PTR list = NULL;
	CK_RV rv = get_function_list(&list);
	if (rv != CKR_OK) {
		return rv;
	}
	CK_C_INITIALIZE_ARGS args;
	memset(&args, 0, sizeof(args));
	args.flags = CKF_OS_LOCKING_OK;
	rv = list->C_Initialize(&args);
	if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
		return rv;
	}
	fl = list;
	return CKR_OK;
}

void p11_close_session(void) {
	if (fl && session != CK_INVALID_HANDLE) {
		fl->C_CloseSession(session);
	}
	session = CK_INVALID_HANDLE;
}

void p11_finalize(void) {
	p11_close_session();
	if (fl) {
		fl->C_Finalize(NULL);
	}
	fl = NULL;
}

unsigned long p11_open_session(void) {
	if (!fl) {
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	CK_SLOT_ID slots[16];
	CK_ULONG count = 16;
	CK_RV rv = fl->C_GetSlotList(CK_TRUE, slots, &count);
	if (rv != CKR_OK) {
		return rv;
	}
	if (count == 0) {
		return P11_ERR_NO_TOKEN;
	}
	// Open the new session before closing the old one: the token logs out when an
	// application's last session closes, and that would force the user to type the PIN again.
	CK_SESSION_HANDLE fresh = CK_INVALID_HANDLE;
	rv = fl->C_OpenSession(slots[0], CKF_SERIAL_SESSION, NULL, NULL, &fresh);
	if (rv != CKR_OK) {
		return rv;
	}
	p11_close_session();
	session = fresh;
	return CKR_OK;
}

static CK_RV find_one(CK_ATTRIBUTE *templ, CK_ULONG templ_count, CK_OBJECT_HANDLE *out) {
	CK_RV rv = fl->C_FindObjectsInit(session, templ, templ_count);
	if (rv != CKR_OK) {
		return rv;
	}
	CK_ULONG found = 0;
	rv = fl->C_FindObjects(session, out, 1, &found);
	fl->C_FindObjectsFinal(session);
	if (rv != CKR_OK) {
		return rv;
	}
	if (found == 0) {
		return P11_ERR_NOT_FOUND;
	}
	return CKR_OK;
}

static CK_RV find_private_key(const uint8_t *key_id, size_t key_id_len, CK_OBJECT_HANDLE *key) {
	CK_OBJECT_CLASS cls = CKO_PRIVATE_KEY;
	CK_ATTRIBUTE templ[] = {
		{ CKA_CLASS, &cls, sizeof(cls) },
		{ CKA_ID, (void *)key_id, key_id_len },
	};
	return find_one(templ, 2, key);
}

static void copy_padded(char *out, size_t out_size, const CK_UTF8CHAR *in, size_t in_len) {
	// PKCS#11 strings are blank-padded and not NUL-terminated.
	size_t len = in_len;
	while (len > 0 && in[len - 1] == ' ') {
		len--;
	}
	if (len >= out_size) {
		len = out_size - 1;
	}
	memcpy(out, in, len);
	out[len] = '\0';
}

unsigned long p11_token_info(char *label, size_t label_size, char *serial, size_t serial_size) {
	CK_SESSION_INFO session_info;
	CK_RV rv = fl->C_GetSessionInfo(session, &session_info);
	if (rv != CKR_OK) {
		return rv;
	}
	CK_TOKEN_INFO info;
	rv = fl->C_GetTokenInfo(session_info.slotID, &info);
	if (rv != CKR_OK) {
		return rv;
	}
	copy_padded(label, label_size, info.label, sizeof(info.label));
	copy_padded(serial, serial_size, info.serialNumber, sizeof(info.serialNumber));
	return CKR_OK;
}

unsigned long p11_certificate_at(size_t index, uint8_t *der, size_t *der_len,
                                 uint8_t *key_id, size_t *key_id_len, unsigned long *category) {
	CK_OBJECT_CLASS cls = CKO_CERTIFICATE;
	CK_ATTRIBUTE templ[] = { { CKA_CLASS, &cls, sizeof(cls) } };
	CK_OBJECT_HANDLE certs[64];
	CK_ULONG found = 0;
	CK_RV rv = fl->C_FindObjectsInit(session, templ, 1);
	if (rv != CKR_OK) {
		return rv;
	}
	rv = fl->C_FindObjects(session, certs, 64, &found);
	fl->C_FindObjectsFinal(session);
	if (rv != CKR_OK) {
		return rv;
	}
	if (index >= found) {
		return P11_ERR_NOT_FOUND;
	}

	CK_ATTRIBUTE attrs[] = {
		{ CKA_VALUE, der, *der_len },
		{ CKA_ID, key_id, *key_id_len },
	};
	rv = fl->C_GetAttributeValue(session, certs[index], attrs, 2);
	if (rv == CKR_BUFFER_TOO_SMALL) {
		return P11_ERR_BUFFER;
	}
	if (rv != CKR_OK) {
		return rv;
	}
	*der_len = attrs[0].ulValueLen;
	*key_id_len = attrs[1].ulValueLen;

	// Optional attribute: 2 means a CA certificate, which has no private key on the token.
	CK_ULONG value = 0;
	CK_ATTRIBUTE category_attr = { CKA_CERTIFICATE_CATEGORY, &value, sizeof(value) };
	*category = fl->C_GetAttributeValue(session, certs[index], &category_attr, 1) == CKR_OK ? value : 0;
	return CKR_OK;
}

unsigned long p11_session_logged_in(int *logged_in) {
	CK_SESSION_INFO info;
	CK_RV rv = fl->C_GetSessionInfo(session, &info);
	if (rv != CKR_OK) {
		return rv;
	}
	*logged_in = info.state == CKS_RO_USER_FUNCTIONS || info.state == CKS_RW_USER_FUNCTIONS;
	return CKR_OK;
}

unsigned long p11_login(const char *pin) {
	CK_RV rv = fl->C_Login(session, CKU_USER, (CK_UTF8CHAR_PTR)pin, strlen(pin));
	if (rv == CKR_USER_ALREADY_LOGGED_IN) {
		return CKR_OK;
	}
	return rv;
}

unsigned long p11_key_always_authenticate(const uint8_t *key_id, size_t key_id_len, int *always) {
	CK_OBJECT_HANDLE key;
	CK_RV rv = find_private_key(key_id, key_id_len, &key);
	if (rv != CKR_OK) {
		return rv;
	}
	CK_BBOOL value = CK_FALSE;
	CK_ATTRIBUTE attr = { CKA_ALWAYS_AUTHENTICATE, &value, sizeof(value) };
	rv = fl->C_GetAttributeValue(session, key, &attr, 1);
	if (rv == CKR_ATTRIBUTE_TYPE_INVALID) {
		*always = 0;
		return CKR_OK;
	}
	if (rv != CKR_OK) {
		return rv;
	}
	*always = value == CK_TRUE;
	return CKR_OK;
}

unsigned long p11_sign_rsa_pkcs(const uint8_t *key_id, size_t key_id_len,
                                const uint8_t *data, size_t data_len,
                                const char *context_pin,
                                uint8_t *sig, size_t *sig_len) {
	CK_OBJECT_HANDLE key;
	CK_RV rv = find_private_key(key_id, key_id_len, &key);
	if (rv != CKR_OK) {
		return rv;
	}
	CK_MECHANISM mech = { CKM_RSA_PKCS, NULL, 0 };
	rv = fl->C_SignInit(session, &mech, key);
	if (rv != CKR_OK) {
		return rv;
	}
	if (context_pin) {
		rv = fl->C_Login(session, CKU_CONTEXT_SPECIFIC, (CK_UTF8CHAR_PTR)context_pin, strlen(context_pin));
		if (rv != CKR_OK) {
			return rv;
		}
	}
	CK_ULONG len = *sig_len;
	rv = fl->C_Sign(session, (CK_BYTE_PTR)data, data_len, sig, &len);
	if (rv != CKR_OK) {
		return rv;
	}
	*sig_len = len;
	return CKR_OK;
}
