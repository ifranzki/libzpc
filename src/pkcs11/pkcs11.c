// SPDX-License-Identifier: MIT
// Copyright contributors to the libzpc project
#include <string.h>
#include <pthread.h>
#include "pkcs11.h"
#include "openssl.h"
#include "config.h"
#include "object.h"
#include "session.h"

#define PKCS11_MANUFACTURER	"IBM"
#define PKCS11_LIBRARY_DESC	"ZPC PKCS#11 provider"
#define PKCS11_SLOT_DESC	"ZPC PKCS#11 slot"
#define PKCS11_TOKEN_LABEL	"ZPC"
#define PKCS11_TOKEN_MODEL	"ZPC"
#define PKCS11_TOKEN_SN		"01"
#define PKCS11_SLOT_NUMBER	0

CK_RV C_Finalize(CK_VOID_PTR pReserved);

/*
 * As per PKCS#11 spec, C_Initialize and C_Finalize are both single-threaded.
 * It is the application's responsibility to ensure C_Initialize and C_Finalize
 * are not called concurrently with each other or with any other C_ function.
 * This no locking is needed or the api_initialized flag.
 */
static volatile CK_BBOOL api_initialized = CK_FALSE;
static pthread_once_t atfork_once = PTHREAD_ONCE_INIT;

static struct {
	CK_MECHANISM_TYPE type;
	CK_MECHANISM_INFO info;
} mech_list[] = {
	{ CKM_ECDSA, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA1, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA224, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA256, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA384, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA512, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_224, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_256, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_384, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_ECDSA_SHA3_512, {256, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_UNCOMPRESS | CKF_EC_COMPRESS}},
	{ CKM_EDDSA, {255, 448, CKF_SIGN | CKF_VERIFY | CKF_EC_OID |
			CKF_EC_F_P | CKF_EC_COMPRESS}},
};
static size_t mech_list_len = sizeof(mech_list) / sizeof(mech_list[0]);

/* General purpose functions */

static void child_fork_initializer(void)
{
	C_Finalize(NULL);
}

static void register_atfork(void)
{
	pthread_atfork(NULL, NULL, child_fork_initializer);
}

CK_RV C_Initialize(CK_VOID_PTR pInitArgs)
{
	CK_C_INITIALIZE_ARGS *pArgs = pInitArgs;

	if (api_initialized)
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;

	if (pArgs != NULL) {
		if (pArgs->pReserved != NULL)
			return CKR_ARGUMENTS_BAD;
		if ((pArgs->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) != 0)
			return CKR_ARGUMENTS_BAD;
		if ((pArgs->flags & CKF_OS_LOCKING_OK) == 0 &&
		    (pArgs->CreateMutex != NULL || pArgs->DestroyMutex != NULL ||
		     pArgs->LockMutex != NULL || pArgs->UnlockMutex != NULL))
			return CKR_CANT_LOCK;
	}

	if (openssl_init() != 1)
		goto cleanup;

	if (session_list_init() != 1)
		goto cleanup;

	if (object_list_init() != 1)
		goto cleanup;

	if (config_process(openssl_process_config) != 1)
		goto cleanup;

	pthread_once(&atfork_once, register_atfork);

	api_initialized = CK_TRUE;
	return CKR_OK;

cleanup:
	object_list_term();
	session_list_term();
	openssl_term();
	return CKR_FUNCTION_FAILED;
}

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	if (pReserved != NULL)
		return CKR_ARGUMENTS_BAD;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	object_list_term();
	session_list_term();
	openssl_term();

	api_initialized = CK_FALSE;
	return CKR_OK;
}

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	pInfo->cryptokiVersion.major = 3;
	pInfo->cryptokiVersion.minor = 2;

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	pInfo->flags = 0;

	memset(pInfo->libraryDescription, ' ',
	       sizeof(pInfo->libraryDescription));
	memcpy(pInfo->libraryDescription, PKCS11_LIBRARY_DESC,
	       strlen(PKCS11_LIBRARY_DESC));

	pInfo->libraryVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->libraryVersion.minor = ZPCPKCS11_VERSION_MINOR;

	return CKR_OK;
}

/* Slot and token management functions */

CK_RV C_GetSlotList(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
		    CK_ULONG_PTR pulCount)
{
	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	(void)tokenPresent;

	if (pSlotList != NULL) {
		if (*pulCount < 1)
			return CKR_BUFFER_TOO_SMALL;

		pSlotList[0] = PKCS11_SLOT_NUMBER;
	}

	*pulCount = 1;

	return CKR_OK;
}

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	memset(pInfo->slotDescription, ' ', sizeof(pInfo->slotDescription));
	memcpy(pInfo->slotDescription, PKCS11_SLOT_DESC,
	       strlen(PKCS11_SLOT_DESC));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	pInfo->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;

	pInfo->hardwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	pInfo->firmwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	return CKR_OK;
}

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	memset(pInfo->label, ' ', sizeof(pInfo->label));
	memcpy(pInfo->label, PKCS11_TOKEN_LABEL, strlen(PKCS11_TOKEN_LABEL));

	memset(pInfo->manufacturerID, ' ', sizeof(pInfo->manufacturerID));
	memcpy(pInfo->manufacturerID, PKCS11_MANUFACTURER,
	       strlen(PKCS11_MANUFACTURER));

	memset(pInfo->model, ' ', sizeof(pInfo->model));
	memcpy(pInfo->model, PKCS11_TOKEN_MODEL, strlen(PKCS11_TOKEN_MODEL));

	memset(pInfo->serialNumber, ' ', sizeof(pInfo->serialNumber));
	memcpy(pInfo->serialNumber, PKCS11_TOKEN_SN, strlen(PKCS11_TOKEN_SN));

	pInfo->flags = CKF_WRITE_PROTECTED | CKF_USER_PIN_INITIALIZED |
		       CKF_TOKEN_INITIALIZED;

	pInfo->ulMaxSessionCount = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE;

	if (!session_get_counts(&pInfo->ulSessionCount,
				&pInfo->ulRwSessionCount))
		return CKR_FUNCTION_FAILED;

	pInfo->ulMaxPinLen = CK_EFFECTIVELY_INFINITE;
	pInfo->ulMinPinLen = 0;
	pInfo->ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION;
	pInfo->ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION;

	pInfo->hardwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->hardwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	pInfo->firmwareVersion.major = ZPCPKCS11_VERSION_MAJOR;
	pInfo->firmwareVersion.minor = ZPCPKCS11_VERSION_MINOR;

	memset(pInfo->utcTime, ' ', sizeof(pInfo->utcTime));

	return CKR_OK;
}

CK_RV C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
			 CK_VOID_PTR pReserved)
{
	(void)flags;
	(void)pSlot;
	(void)pReserved;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
			 CK_MECHANISM_TYPE_PTR pMechanismList,
			 CK_ULONG_PTR pulCount)
{
	CK_ULONG i;

	if (pulCount == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	if (pMechanismList == NULL) {
		*pulCount = mech_list_len;
		return CKR_OK;
	}

	if (*pulCount < mech_list_len) {
		*pulCount = mech_list_len;
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < mech_list_len; i++)
		pMechanismList[i] = mech_list[i].type;
	*pulCount = mech_list_len;

	return CKR_OK;
}

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
			 CK_MECHANISM_INFO_PTR pInfo)
{
	CK_ULONG i;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	for (i = 0; i < mech_list_len; i++) {
		if (mech_list[i].type == type) {
			*pInfo = mech_list[i].info;
			return CKR_OK;
		}
	}

	return CKR_MECHANISM_INVALID;
}

CK_RV C_InitToken(CK_SLOT_ID slotID, CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pLabel)
{
	(void)slotID;
	(void)pPin;
	(void)ulPinLen;
	(void)pLabel;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pPin,
		CK_ULONG ulPinLen)
{
	(void)hSession;
	(void)pPin;
	(void)ulPinLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pOldPin,
	       CK_ULONG ulOldLen, CK_UTF8CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	(void)hSession;
	(void)pOldPin;
	(void)ulOldLen;
	(void)pNewPin;
	(void)ulNewLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Session management functions */

CK_RV C_OpenSession(CK_SLOT_ID slotID, CK_FLAGS flags, CK_VOID_PTR pApplication,
		    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{
	(void)Notify;
	(void)pApplication;

	if (phSession == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;
	if ((flags & CKF_SERIAL_SESSION) == 0)
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	if ((flags & CKF_ASYNC_SESSION) != 0)
		return CKR_SESSION_ASYNC_NOT_SUPPORTED;

	if (!session_add_session(slotID, flags, phSession))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_remove_session(hSession))
		return CKR_SESSION_HANDLE_INVALID;

	return CKR_OK;
}

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (slotID != PKCS11_SLOT_NUMBER)
		return CKR_SLOT_ID_INVALID;

	if (!session_remove_all())
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	struct pkcs11_session *sess;

	if (pInfo == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	*pInfo = sess->info;
	return CKR_OK;
}

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG_PTR pulOperationStateLen)
{
	(void)hSession;
	(void)pOperationState;
	(void)pulOperationStateLen;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_STATE_UNSAVEABLE;
}

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
			  CK_BYTE_PTR pOperationState,
			  CK_ULONG ulOperationStateLen,
			  CK_OBJECT_HANDLE hEncryptionKey,
			  CK_OBJECT_HANDLE hAuthenticationKey)
{
	(void)hSession;
	(void)pOperationState;
	(void)ulOperationStateLen;
	(void)hEncryptionKey;
	(void)hAuthenticationKey;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	return CKR_STATE_UNSAVEABLE;
}

CK_RV C_Login(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
	      CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	struct pkcs11_session *sess;

	(void)pPin;
	(void)ulPinLen;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_TRUE)
		return CKR_USER_ALREADY_LOGGED_IN;

	session_set_login_state(CK_TRUE);

	return CKR_OK;
}

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{
	struct pkcs11_session *sess;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_FALSE)
		return CKR_USER_NOT_LOGGED_IN;

	session_set_login_state(CK_FALSE);

	return CKR_OK;
}

CK_RV C_SessionCancel(CK_SESSION_HANDLE hSession, CK_FLAGS flags)
{
	struct pkcs11_session *sess;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!session_op_cleanup(sess, flags))
		return CKR_OPERATION_CANCEL_FAILED;

	return CKR_OK;
}

/* Object management functions */

CK_RV C_CreateObject(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{
	(void)hSession;
	(void)pTemplate;
	(void)ulCount;
	(void)phObject;
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		   CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		   CK_OBJECT_HANDLE_PTR phNewObject)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	(void)phNewObject;
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{
	(void)hSession;
	(void)hObject;
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
		      CK_ULONG_PTR pulSize)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;

	if (pulSize == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hObject, &obj))
		return CKR_OBJECT_HANDLE_INVALID;

	if (!object_get_size(obj, pulSize))
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;

	if (pTemplate == NULL && ulCount != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (!object_list_get(hObject, &obj))
		return CKR_OBJECT_HANDLE_INVALID;

	return object_get_attributes(obj, pTemplate, ulCount);
}

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
			  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	(void)hSession;
	(void)hObject;
	(void)pTemplate;
	(void)ulCount;
	return CKR_TOKEN_WRITE_PROTECTED;
}

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
			CK_ULONG ulCount)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (pTemplate == NULL && ulCount != 0)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_init(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	sess->find.pos = 0;
	if (!dyn_array_init(&sess->find.found)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (!object_list_find(pTemplate, ulCount, &sess->find.found)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	if (rc != CKR_OK)
		session_op_cleanup(sess, CKF_FIND_OBJECTS);

	return rc;
}

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE_PTR phObject,
		    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	struct pkcs11_session *sess;
	struct pkcs11_object *obj;
	CK_ULONG i;
	CK_RV rc;

	if (phObject == NULL || pulObjectCount == NULL)
		return CKR_ARGUMENTS_BAD;
	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	*pulObjectCount = 0;
	for (i = 0; i < ulMaxObjectCount; i++) {
		if (!dyn_array_get(&sess->find.found, sess->find.pos,
				   (void **)&obj))
			break;

		phObject[i] = obj->handle;
		(*pulObjectCount)++;
		sess->find.pos++;
	}

	return CKR_OK;
}

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{
	struct pkcs11_session *sess;
	CK_RV rc;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	rc = session_op_multi(sess, CKF_FIND_OBJECTS);
	if (rc != CKR_OK)
		return rc;

	session_op_cleanup(sess, CKF_FIND_OBJECTS);

	return CKR_OK;
}

/* Encryption functions */

CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
	      CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_ENCRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		CK_ULONG ulDataLen, CK_BYTE_PTR pEncryptedData,
		CK_ULONG_PTR pulEncryptedDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pEncryptedData;
	(void)pulEncryptedDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastEncryptedPart,
		     CK_ULONG_PTR pulLastEncryptedPartLen)
{
	(void)hSession;
	(void)pLastEncryptedPart;
	(void)pulLastEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Decryption functions */

CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_DECRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
		CK_ULONG ulEncryptedDataLen, CK_BYTE_PTR pData,
		CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pEncryptedData;
	(void)ulEncryptedDataLen;
	(void)pData;
	(void)pulDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
		      CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
		     CK_ULONG_PTR pulLastPartLen)
{
	(void)hSession;
	(void)pLastPart;
	(void)pulLastPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Message digesting functions */

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_DIGEST);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Digest(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
	       CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pDigest;
	(void)pulDigestLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	(void)hSession;
	(void)hKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
		    CK_ULONG_PTR pulDigestLen)
{
	(void)hSession;
	(void)pDigest;
	(void)pulDigestLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Signing and MACing functions */

CK_RV C_SignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_SIGN);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Sign(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData, CK_ULONG ulDataLen,
	     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		   CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		  CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_SIGN_RECOVER);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		    CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Verifying signatures and MACs functions */

CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_VERIFY);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_Verify(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
	       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	       CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
		     CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		    CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_VERIFY_RECOVER);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
		      CK_ULONG ulSignatureLen, CK_BYTE_PTR pData,
		      CK_ULONG_PTR pulDataLen)
{
	(void)hSession;
	(void)pSignature;
	(void)ulSignatureLen;
	(void)pData;
	(void)pulDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Dual-function cryptographic functions */

CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			    CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			  CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			  CK_ULONG_PTR pulEncryptedPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	(void)pEncryptedPart;
	(void)pulEncryptedPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
			    CK_BYTE_PTR pEncryptedPart,
			    CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			    CK_ULONG_PTR pulPartLen)
{
	(void)hSession;
	(void)pEncryptedPart;
	(void)ulEncryptedPartLen;
	(void)pPart;
	(void)pulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Key management functions */

CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		    CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)pTemplate;
	(void)ulCount;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			CK_ULONG ulPublicKeyAttributeCount,
			CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			CK_ULONG ulPrivateKeyAttributeCount,
			CK_OBJECT_HANDLE_PTR phPublicKey,
			CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)pPublicKeyTemplate;
	(void)ulPublicKeyAttributeCount;
	(void)pPrivateKeyTemplate;
	(void)ulPrivateKeyAttributeCount;
	(void)phPublicKey;
	(void)phPrivateKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
		CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)hSession;
	(void)pMechanism;
	(void)hWrappingKey;
	(void)hKey;
	(void)pWrappedKey;
	(void)pulWrappedKeyLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
		  CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hUnwrappingKey;
	(void)pWrappedKey;
	(void)ulWrappedKeyLen;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		  CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
		  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hBaseKey;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Random number generation functions */

CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
		   CK_ULONG ulSeedLen)
{
	(void)hSession;
	(void)pSeed;
	(void)ulSeedLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
		       CK_ULONG ulRandomLen)
{
	(void)hSession;
	(void)pRandomData;
	(void)ulRandomLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Parallel function management functions */

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_PARALLEL;
}

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	(void)hSession;

	return CKR_FUNCTION_NOT_PARALLEL;
}

/* Message-based encryption and decryption functions (v3.0) */

CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism,
			   CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_MESSAGE_ENCRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG ulPlaintextLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	(void)pPlaintext;
	(void)ulPlaintextLen;
	(void)pCiphertext;
	(void)pulCiphertextLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG ulPlaintextPartLen,
			   CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG_PTR pulCiphertextPartLen, CK_FLAGS flags)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pPlaintextPart;
	(void)ulPlaintextPartLen;
	(void)pCiphertextPart;
	(void)pulCiphertextPartLen;
	(void)flags;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE hSession,
			   CK_MECHANISM_PTR pMechanism,
			   CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_MESSAGE_DECRYPT);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		       CK_ULONG ulParameterLen, CK_BYTE_PTR pAssociatedData,
		       CK_ULONG ulAssociatedDataLen, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_BYTE_PTR pPlaintext,
		       CK_ULONG_PTR pulPlaintextLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	(void)pCiphertext;
	(void)ulCiphertextLen;
	(void)pPlaintext;
	(void)pulPlaintextLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			    CK_ULONG ulParameterLen,
			    CK_BYTE_PTR pAssociatedData,
			    CK_ULONG ulAssociatedDataLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pAssociatedData;
	(void)ulAssociatedDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen, CK_BYTE_PTR pCiphertextPart,
			   CK_ULONG ulCiphertextPartLen,
			   CK_BYTE_PTR pPlaintextPart,
			   CK_ULONG_PTR pulPlaintextPartLen, CK_FLAGS flags)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pCiphertextPart;
	(void)ulCiphertextPartLen;
	(void)pPlaintextPart;
	(void)pulPlaintextPartLen;
	(void)flags;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Message-based signing and verification functions (v3.0) */

CK_RV C_MessageSignInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
			CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_MESSAGE_SIGN);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		    CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		    CK_ULONG ulDataLen,
		    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			 CK_ULONG ulParameterLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_SignMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			CK_ULONG_PTR pulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)pulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageSignFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE hSession,
			  CK_MECHANISM_PTR pMechanism,
			  CK_OBJECT_HANDLE hKey)
{
	(void)hKey;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_MESSAGE_VERIFY);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessage(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
		      CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
		      CK_ULONG ulDataLen,
		      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			   CK_ULONG ulParameterLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE hSession, CK_VOID_PTR pParameter,
			  CK_ULONG ulParameterLen, CK_BYTE_PTR pData,
			  CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
			  CK_ULONG ulSignatureLen)
{
	(void)hSession;
	(void)pParameter;
	(void)ulParameterLen;
	(void)pData;
	(void)ulDataLen;
	(void)pSignature;
	(void)ulSignatureLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* PKCS #11 v3.2 functions */

CK_RV C_LoginUser(CK_SESSION_HANDLE hSession, CK_USER_TYPE userType,
		  CK_UTF8CHAR_PTR pPin, CK_ULONG ulPinLen,
		  CK_UTF8CHAR_PTR pUsername, CK_ULONG ulUsernameLen)
{
	struct pkcs11_session *sess;

	(void)pPin;
	(void)ulPinLen;
	(void)pUsername;
	(void)ulUsernameLen;

	if (!api_initialized)
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	if (userType != CKU_USER)
		return CKR_USER_TYPE_INVALID;

	if (!session_get_session(hSession, &sess))
		return CKR_SESSION_HANDLE_INVALID;

	if (session_get_login_state() == CK_TRUE)
		return CKR_USER_ALREADY_LOGGED_IN;

	session_set_login_state(CK_TRUE);

	return CKR_OK;
}

CK_RV C_EncapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		       CK_OBJECT_HANDLE hPublicKey, CK_ATTRIBUTE_PTR pTemplate,
		       CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
		       CK_ULONG_PTR pulCiphertextLen,
		       CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hPublicKey;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)pCiphertext;
	(void)pulCiphertextLen;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_DecapsulateKey(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
		       CK_OBJECT_HANDLE hPrivateKey, CK_ATTRIBUTE_PTR pTemplate,
		       CK_ULONG ulAttributeCount, CK_BYTE_PTR pCiphertext,
		       CK_ULONG ulCiphertextLen, CK_OBJECT_HANDLE_PTR phKey)
{
	(void)hSession;
	(void)pMechanism;
	(void)hPrivateKey;
	(void)pTemplate;
	(void)ulAttributeCount;
	(void)pCiphertext;
	(void)ulCiphertextLen;
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureInit(CK_SESSION_HANDLE hSession,
			    CK_MECHANISM_PTR pMechanism,
			    CK_OBJECT_HANDLE hKey,
			    CK_BYTE_PTR pSignature,
			    CK_ULONG ulSignatureLen)
{
	(void)hKey;
	(void)pSignature;
	(void)ulSignatureLen;

	if (pMechanism == NULL)
		return C_SessionCancel(hSession, CKF_SIGN);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignature(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
			CK_ULONG ulDataLen)
{
	(void)hSession;
	(void)pData;
	(void)ulDataLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
			      CK_ULONG ulPartLen)
{
	(void)hSession;
	(void)pPart;
	(void)ulPartLen;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_VerifySignatureFinal(CK_SESSION_HANDLE hSession)
{
	(void)hSession;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_GetSessionValidationFlags(CK_SESSION_HANDLE hSession,
				  CK_SESSION_VALIDATION_FLAGS_TYPE type,
				  CK_FLAGS_PTR pFlags)
{
	(void)hSession;
	(void)type;
	(void)pFlags;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncComplete(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		      CK_ASYNC_DATA_PTR pResult)
{
	(void)hSession;
	(void)pFunctionName;
	(void)pResult;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncGetID(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		   CK_ULONG_PTR pulID)
{
	(void)hSession;
	(void)pFunctionName;
	(void)pulID;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_AsyncJoin(CK_SESSION_HANDLE hSession, CK_UTF8CHAR_PTR pFunctionName,
		  CK_ULONG ulID, CK_BYTE_PTR pData, CK_ULONG ulData)
{
	(void)hSession;
	(void)pFunctionName;
	(void)ulID;
	(void)pData;
	(void)ulData;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_WrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
			     CK_MECHANISM_PTR pMechanism,
			     CK_OBJECT_HANDLE hWrappingKey,
			     CK_OBJECT_HANDLE hKey,
			     CK_BYTE_PTR pAssociatedData,
			     CK_ULONG ulAssociatedDataLen,
			     CK_BYTE_PTR pWrappedKey,
			     CK_ULONG_PTR pulWrappedKeyLen)
{
	(void)(hSession);
	(void)(pMechanism);
	(void)(hWrappingKey);
	(void)(hKey);
	(void)(pAssociatedData);
	(void)(ulAssociatedDataLen);
	(void)(pWrappedKey);
	(void)(pulWrappedKeyLen);
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV C_UnwrapKeyAuthenticated(CK_SESSION_HANDLE hSession,
			       CK_MECHANISM_PTR pMechanism,
			       CK_OBJECT_HANDLE hUnwrappingKey,
			       CK_BYTE_PTR pWrappedKey,
			       CK_ULONG ulWrappedKeyLen,
			       CK_ATTRIBUTE_PTR pTemplate,
			       CK_ULONG ulAttributeCount,
			       CK_BYTE_PTR pAssociatedData,
			       CK_ULONG ulAssociatedDataLen,
			       CK_OBJECT_HANDLE_PTR phKey)
{
	(void)(hSession);
	(void)(pMechanism);
	(void)(hUnwrappingKey);
	(void)(pWrappedKey);
	(void)ulWrappedKeyLen;
	(void)(pTemplate);
	(void)(ulAttributeCount);
	(void)(pAssociatedData);
	(void)(ulAssociatedDataLen);
	(void)phKey;
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Interface lists and related functions */

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
			 CK_ULONG_PTR pulCount);
CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags);

static CK_FUNCTION_LIST func_list_pkcs11_2_40 = {
	{2, 40},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

static CK_FUNCTION_LIST_3_0 func_list_pkcs11_3_0 = {
	{3, 0},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent,
	C_GetInterfaceList,
	C_GetInterface,
	C_LoginUser,
	C_SessionCancel,
	C_MessageEncryptInit,
	C_EncryptMessage,
	C_EncryptMessageBegin,
	C_EncryptMessageNext,
	C_MessageEncryptFinal,
	C_MessageDecryptInit,
	C_DecryptMessage,
	C_DecryptMessageBegin,
	C_DecryptMessageNext,
	C_MessageDecryptFinal,
	C_MessageSignInit,
	C_SignMessage,
	C_SignMessageBegin,
	C_SignMessageNext,
	C_MessageSignFinal,
	C_MessageVerifyInit,
	C_VerifyMessage,
	C_VerifyMessageBegin,
	C_VerifyMessageNext,
	C_MessageVerifyFinal
};

static CK_FUNCTION_LIST_3_2 func_list_pkcs11_3_2 = {
	{3, 2},
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent,
	C_GetInterfaceList,
	C_GetInterface,
	C_LoginUser,
	C_SessionCancel,
	C_MessageEncryptInit,
	C_EncryptMessage,
	C_EncryptMessageBegin,
	C_EncryptMessageNext,
	C_MessageEncryptFinal,
	C_MessageDecryptInit,
	C_DecryptMessage,
	C_DecryptMessageBegin,
	C_DecryptMessageNext,
	C_MessageDecryptFinal,
	C_MessageSignInit,
	C_SignMessage,
	C_SignMessageBegin,
	C_SignMessageNext,
	C_MessageSignFinal,
	C_MessageVerifyInit,
	C_VerifyMessage,
	C_VerifyMessageBegin,
	C_VerifyMessageNext,
	C_MessageVerifyFinal,
	C_EncapsulateKey,
	C_DecapsulateKey,
	C_VerifySignatureInit,
	C_VerifySignature,
	C_VerifySignatureUpdate,
	C_VerifySignatureFinal,
	C_GetSessionValidationFlags,
	C_AsyncComplete,
	C_AsyncGetID,
	C_AsyncJoin,
	C_WrapKeyAuthenticated,
	C_UnwrapKeyAuthenticated
};

static CK_INTERFACE interfaces[] = {
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_3_2,
		CKF_INTERFACE_FORK_SAFE
	},
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_3_0,
		CKF_INTERFACE_FORK_SAFE
	},
	{
		(CK_UTF8CHAR *)"PKCS 11",
		&func_list_pkcs11_2_40,
		CKF_INTERFACE_FORK_SAFE
	},
};

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	if (ppFunctionList == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	*ppFunctionList = &func_list_pkcs11_2_40;
	return CKR_OK;
}

CK_RV C_GetInterfaceList(CK_INTERFACE_PTR pInterfacesList,
			 CK_ULONG_PTR pulCount)
{
	if (pulCount == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	if (pInterfacesList == NULL_PTR) {
		*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
		return CKR_OK;
	}

	if (*pulCount < sizeof(interfaces) / sizeof(interfaces[0])) {
		*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
		return CKR_BUFFER_TOO_SMALL;
	}

	*pulCount = sizeof(interfaces) / sizeof(interfaces[0]);
	for (CK_ULONG i = 0; i < *pulCount; i++)
		pInterfacesList[i] = interfaces[i];

	return CKR_OK;
}

CK_RV C_GetInterface(CK_UTF8CHAR_PTR pInterfaceName, CK_VERSION_PTR pVersion,
		     CK_INTERFACE_PTR_PTR ppInterface, CK_FLAGS flags)
{
	CK_INTERFACE *interf;
	size_t i;

	if (ppInterface == NULL_PTR)
		return CKR_ARGUMENTS_BAD;

	*ppInterface = NULL;
	for (i = 0; i < sizeof(interfaces) / sizeof(interfaces[0]); i++) {
		interf = &interfaces[i];

		if ((pInterfaceName == NULL ||
		     (pInterfaceName != NULL &&
		      strcmp((char *)pInterfaceName,
			     (char *)interf->pInterfaceName) == 0)) &&
		    (pVersion == NULL ||
		     (pVersion->major ==
			     ((CK_VERSION *)interf->pFunctionList)->major &&
		      pVersion->minor ==
			     ((CK_VERSION *)interf->pFunctionList)->minor)) &&
		    (flags == (interf->flags & flags))) {
			*ppInterface = interf;
			break;
		}
	}

	if (*ppInterface == NULL)
		return CKR_FUNCTION_FAILED;

	return CKR_OK;
}
