#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "base64.h"
#include <sys/ptrace.h>
#include <SKF.h>
#include "logger.h"
#include "APDUs.h"

// 获取数组的大小
# define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
// 指定要注册的类，对应完整的java类名
#define JNIREG_CLASS "com/tongxin/sdjni/SdEncrypt"

jstring charToJstring(JNIEnv *envPtr, char *src) {
    JNIEnv env = *envPtr;

    jsize len = strlen(src);
    jclass clsstring = env->FindClass(envPtr, "java/lang/String");
    jstring strencode = env->NewStringUTF(envPtr, "UTF-8");
    jmethodID mid = env->GetMethodID(envPtr, clsstring, "<init>", "([BLjava/lang/String;)V");
    jbyteArray barr = env->NewByteArray(envPtr, len);
    env->SetByteArrayRegion(envPtr, barr, 0, len, (jbyte *) src);

    return (jstring) env->NewObject(envPtr, clsstring, mid, barr, strencode);
}

JNIEXPORT jlong JNICALL set_package(JNIEnv *env, jobject instance, jstring str_) {
    // set package name
    char *pkgname = (char *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    LOGI("set_package package name: %s\n", pkgname);
    // set log path
    memset(SV_PSZLOGPATH, '\0', SIZE_BUFFER_128);
    strcat(SV_PSZLOGPATH, "/storage/emulated/0/Android/data/");
    strcat(SV_PSZLOGPATH, pkgname);
    strcat(SV_PSZLOGPATH, "/files/tmc_sdk.log");
    LOGI("set_package log_name: %s\n", SV_PSZLOGPATH);
    u32 pkgresult = V_SetAppPath(pkgname);
    LOGI("setpackage result: %ld", pkgresult);
    (*env)->ReleaseStringUTFChars(env, str_, pkgname);
    return pkgresult;
}

JNIEXPORT jstring JNICALL get_func_list(JNIEnv *env, jobject instance) {
    PSKF_FUNCLIST funcList;
    unsigned long baseResult = SKF_GetFuncList( funcList );
    LOGI("get_func_list baseResult: %ld", baseResult);
    LOGI("get_func_list major: %d\n", funcList->version.major);
    LOGI("get_func_list minor: %d\n", funcList->version.minor);
    // just for test
//    SKF_WRITE_LOG_FILE = 1;
//    WriteLogToFile(funcList);
//    SKF_WRITE_LOG_FILE = 0;
//    jstring  result = charToJstring(env, funcList);
//    return result;
    return (*env)->NewStringUTF(env, '\0');
}

JNIEXPORT jlong JNICALL import_cert(JNIEnv *env, jobject instance, jint handle, jbyteArray str_) {
    LOGI("import_cert handle: %d", handle);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    u8 * pbCommand = (unsigned char*) bBuffer;
    LOGI("import_cert pbCommand: %s\n", pbCommand);
//    LOGI("import_cert pbCommand size: %d\n", strlen(pbCommand));
    if (pbCommand == NULL) {
        LOGE("transmit_ex with null string.");
        return -1;
    }
    HCONTAINER hContainer;
    u32 ulCertLen = sizeof(pbCommand)/ sizeof(pbCommand[0]);
    unsigned long baseResult = SKF_ImportCertificate(hContainer, 1, pbCommand,ulCertLen );
    LOGI("import_cert result: %ld", baseResult);
    (*env)->ReleaseByteArrayElements(env, str_, bBuffer, 0);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL export_cert(JNIEnv *env, jobject instance, jint handle) {
    LOGI("export_cert handle: %d", handle);
    u8 *pbOutData = (char *) malloc(SIZE_BUFFER_1024 * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("export_cert with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SIZE_BUFFER_1024 * sizeof(char));
    u32 pulCertLen = 0;
    HCONTAINER hContainer;
    unsigned long baseResult = SKF_ExportCertificate(hContainer, 1, pbOutData, &pulCertLen);
    LOGI("export_cert result: %ld", baseResult);
    LOGI("export_cert pulCertLen: %ld", pulCertLen);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    jbyte *by = (jbyte*) pbOutData;
    jbyteArray retArray = (*env)->NewByteArray(env, pulCertLen);
    (*env)->SetByteArrayRegion(env, retArray, 0, pulCertLen, by);
    // need free the memory
    free(pbOutData);
    return retArray;
}

JNIEXPORT jstring JNICALL enum_dev(JNIEnv *env, jobject instance) {
    LOGI("enum_dev function.");
    ULONG rv, listLen = 512;
    CHAR devList[512] = { 0 };
    rv = SKF_EnumDev(TRUE, devList, &listLen);
    if (rv != SAR_OK) {
        LOGE("SKF_EnumDev ERROR, errno: %ld\n", rv);
        return (*env)->NewStringUTF(env, '\0');
    }
    LOGI("EnumDev result: %ld", rv);
    LOGI("EnumDev pszDrives: %s\n", devList);
    jstring  result = charToJstring(env, devList);
    // need free the memory
//    free(pszDrives);
    return result;
}

JNIEXPORT jint JNICALL connect_dev(JNIEnv *env, jobject instance, jstring str_) {
    char *szDrive = (char *) (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    if (szDrive == NULL) {
        LOGE("connect_dev with null string.");
        return -1;
    }
    LOGI("connect_dev szDrive: %s\n", szDrive);
    DEVHANDLE pulDriveNum = 0;
    unsigned long baseResult = SKF_ConnectDev(szDrive, &pulDriveNum);
    LOGI("connect_dev baseResult: %ld", baseResult);
    LOGI("connect_dev pulDriveNum: %d", pulDriveNum);
    sv_Device = pulDriveNum;
    (*env)->ReleaseStringUTFChars(env, str_, szDrive);
    if (baseResult == 0) {
        return pulDriveNum;
    } else {
        return baseResult;
    }
}

JNIEXPORT jlong JNICALL disconnect_dev(JNIEnv *env, jobject instance, jint handle) {
    LOGI("disconnect_dev handle: %ld", handle);
    unsigned long baseResult = SKF_DisConnectDev(sv_Device);
    LOGI("disconnect_dev baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jstring JNICALL gen_random(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_random handle: %ld", handle);
    unsigned long keyLen = sizeof (bRandomKey) / sizeof(BYTE);
    unsigned long baseResult = SKF_GenRandom(sv_Device, bRandomKey, &keyLen);
    LOGI("gen_random baseResult: %ld", baseResult);
    LOGI("gen_random pszDrives: %s\n", bRandomKey);
    jstring  result = charToJstring(env, bRandomKey);
    return result;
}

JNIEXPORT jbyteArray JNICALL gen_ecc_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_ecc_key handle: %d", handle);
    ECCPUBLICKEYBLOB sign_pub;
    unsigned long baseResult = SKF_GenECCKeyPair( handle, SGD_SM2_1, &sign_pub );
    LOGI("gen_ecc_key baseResult: %ld", baseResult);
    LOGI("gen_ecc_key pKeyPair: %ld\n", sign_pub.BitLen);
    BYTE keys[SIZE_BUFFER_128] = { 0 };
    memcpy(keys, sign_pub.XCoordinate, SIZE_BUFFER_64);
    memcpy(keys + SIZE_BUFFER_64, sign_pub.YCoordinate, SIZE_BUFFER_64);
    jbyte *by = (jbyte*) keys;
    jbyteArray retArray = (*env)->NewByteArray(env, SIZE_BUFFER_128);
    (*env)->SetByteArrayRegion(env, retArray, 0, SIZE_BUFFER_128, by);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_ecc_key(JNIEnv *env, jobject instance, jint handle, jbyteArray pub, jbyteArray prv) {
    LOGI("import_ecc_key handle: %ld", handle);
    ENVELOPEDKEYBLOB *pEnvelopedKeyBlob;
    // compse ENVELOPEDKEYBLOB
    ULONG envLen = sizeof (ENVELOPEDKEYBLOB) + sizeof(bKeyHandle);
    pEnvelopedKeyBlob = malloc(envLen);
    if (!env) {
        LOGE("import_ecc_key malloc ERROR\n");
        return -1;
    }
    pEnvelopedKeyBlob->Version = 1;
//    pEnvelopedKeyBlob->ulSymmAlgID = SGD_SM1_ECB;
//    pEnvelopedKeyBlob->ulBits = sign_pub.BitLen;
//    memcpy(pEnvelopedKeyBlob->cbEncryptedPriKey, cip, cipLen);

    pEnvelopedKeyBlob->PubKey.BitLen = pEnvelopedKeyBlob->ulBits;
//    memcpy(pEnvelopedKeyBlob->PubKey.XCoordinate + sizeof (pEnvelopedKeyBlob->PubKey.XCoordinate) - sizeof (bEccPrikey),
//           bEccPubkey, sizeof (bEccPrikey));
//    memcpy(pEnvelopedKeyBlob->PubKey.YCoordinate + sizeof (pEnvelopedKeyBlob->PubKey.YCoordinate) - sizeof (bEccPrikey),
//           bEccPubkey + sizeof (bEccPrikey), sizeof (bEccPrikey));

    unsigned long baseResult = SKF_ImportECCKeyPair( handle, pEnvelopedKeyBlob );
    LOGI("import_ecc_key baseResult: %ld", baseResult);
    LOGI("import_ecc_key pubKey: %s\n", pEnvelopedKeyBlob->PubKey.XCoordinate);
    LOGI("import_ecc_key privKey: %s\n", pEnvelopedKeyBlob->cbEncryptedPriKey);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL ecc_sign_data(JNIEnv *env, jobject instance, jint handle, jbyteArray data) {
    LOGI("ecc_sign_data handle: %ld", handle);
    ECCPUBLICKEYBLOB sign_pub;
    ECCSIGNATUREBLOB sig;
    BYTE in[32] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    ULONG rv, inLen, len;

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(sv_Device, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        LOGE("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    inLen = sizeof (in) / sizeof (BYTE);
    rv = SKF_ECCSignData(sv_Device, in, inLen, &sig);
    if (rv != SAR_OK) {
        LOGE("SKF_SignData ERROR, errno[0x%08x]\n", rv);
        goto error;
    }
    LOGI("ecc_sign_data baseResult: %ld", rv);
    CHAR szLog[SIZE_BUFFER_1024] = { 0 };
    LOGI("ecc_sign_data baseResult: %s", sig.r);
    for (int i = 0; i < sizeof(sig.r); i++) {
        sprintf( szLog, "%02x", sig.r[i] );
    }
    LOGI("ecc_sign_data sig.r: %s", szLog);
    BYTE keys[SIZE_BUFFER_128] = { 0 };
    memcpy(keys, sig.r, SIZE_BUFFER_64);
    memcpy(keys + SIZE_BUFFER_64, sig.s, SIZE_BUFFER_64);
    jbyte *by = (jbyte*) keys;
    jbyteArray retArray = (*env)->NewByteArray(env, SIZE_BUFFER_128);
    (*env)->SetByteArrayRegion(env, retArray, 0, SIZE_BUFFER_128, by);
    return retArray;

error:
    return NULL;
}

JNIEXPORT jlong JNICALL ecc_verify(JNIEnv *env, jobject instance, jint handle, jbyteArray sign, jbyteArray data) {
    LOGI("ecc_verify handle: %ld", handle);
    ECCPUBLICKEYBLOB sign_pub;
    ECCSIGNATUREBLOB sig;
    BYTE in[32] = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    ULONG rv, inLen, len;
    int ret = 0;

    // export sign public key
    len = sizeof (sign_pub);
    rv = SKF_ExportPublicKey(sv_Device, 1, (BYTE *)&sign_pub, &len);
    if (rv != SAR_OK) {
        LOGE("SKF_ExportPublicKey sign ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    inLen = sizeof (in) / sizeof (BYTE);
    rv = SKF_ECCSignData(sv_Device, in, inLen, &sig);
    if (rv != SAR_OK) {
        LOGE("SKF_SignData ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    rv = SKF_ECCVerify(sv_Device, &sign_pub, in, inLen, &sig);
    if (rv != SAR_OK) {
        LOGE("SKF_Verify ERROR, errno[0x%08x]\n", rv);
        goto error;
    }

    ret = 1;
error:
    return ret;
}

JNIEXPORT jlong JNICALL ext_ecc_verify(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ext_ecc_verify handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    ECCPUBLICKEYBLOB pECCPubKeyBlob;
    PECCSIGNATUREBLOB pSignature;
    unsigned long baseResult = SKF_ExtECCVerify( handle, &pECCPubKeyBlob, pbData, ulDataLen, pSignature );
    LOGI("ext_ecc_verify baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_data_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_data_ecc handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    ECCPUBLICKEYBLOB pECCPubKeyBlob;
    HANDLE* phAgreementHandle;
    unsigned long baseResult = SKF_GenerateAgreementDataWithECC( handle, SGD_SM2_1, &pECCPubKeyBlob,
            pbData, ulDataLen, phAgreementHandle );
    LOGI("gen_data_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_key_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_key_ecc handle: %ld", handle);
    ULONG ulAlgId;
    ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob;
    ECCPUBLICKEYBLOB pTempECCPubKeyBlob;
    BYTE pbID;
    ULONG ulIDLen;
    HANDLE phKeyHandle;
    unsigned long baseResult = SKF_GenerateKeyWithECC( handle, &pSponsorECCPubKeyBlob,
            &pTempECCPubKeyBlob, &pbID, ulIDLen, &phKeyHandle );
    LOGI("gen_key_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_data_key_ecc(JNIEnv *env, jobject instance, jint handle) {
    LOGI("gen_data_key_ecc handle: %ld", handle);
    ULONG ulAlgId;
    ECCPUBLICKEYBLOB pSponsorECCPubKeyBlob;
    ECCPUBLICKEYBLOB pSponsorTempECCPubKeyBlob;
    ECCPUBLICKEYBLOB pTempECCPubKeyBlob;
    BYTE pbID;
    ULONG ulIDLen;
    BYTE pbSponsorID;
    ULONG ulSponsorIDLen;
    HANDLE phKeyHandle;
    unsigned long baseResult = SKF_GenerateAgreementDataAndKeyWithECC( handle, ulAlgId, &pSponsorECCPubKeyBlob,
            &pSponsorTempECCPubKeyBlob, &pTempECCPubKeyBlob, &pbID, ulIDLen, &pbSponsorID, ulSponsorIDLen, &phKeyHandle );
    LOGI("gen_data_key_ecc baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL export_public_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("export_public_key handle: %ld", handle);
    ECCPUBLICKEYBLOB pubKey;
    ULONG pulBlobLen = sizeof (pubKey);
    unsigned long baseResult = SKF_ExportPublicKey( handle, TRUE, (BYTE *) &pubKey, &pulBlobLen );
    LOGI("export_public_key baseResult: %ld", baseResult);
    LOGI("export_public_key pubKey: %s\n", pubKey);
    BYTE keys[SIZE_BUFFER_128] = { 0 };
    memcpy(keys, pubKey.XCoordinate, SIZE_BUFFER_64);
    memcpy(keys + SIZE_BUFFER_64, pubKey.YCoordinate, SIZE_BUFFER_64);
    jbyte *by = (jbyte*) keys;
    jbyteArray retArray = (*env)->NewByteArray(env, SIZE_BUFFER_128);
    (*env)->SetByteArrayRegion(env, retArray, 0, SIZE_BUFFER_128, by);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_session_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_session_key handle: %ld", handle);
    BYTE* pbBlob;
    ULONG pulBlobLen;
    HANDLE phKey;
    unsigned long baseResult = SKF_ImportSessionKey( handle, SGD_SM2_1, pbBlob, pulBlobLen, &phKey );
    LOGI("import_session_key baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL set_sym_key(JNIEnv *env, jobject instance, jint handle, jbyteArray str_) {
    LOGI("set_sym_key handle: %ld", handle);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    LOGI("set_sym_key pbCommand: %s\n", pbCommand);
    LOGI("set_sym_key pbCommand size: %d\n", strlen(pbCommand));
    if (pbCommand == NULL) {
        LOGE("set_sym_key with null string.");
        return -1;
    }
    unsigned long baseResult = SKF_SetSymmKey( handle, bRandomKey, SGD_SM1, bKeyHandle );
    LOGI("set_sym_key baseResult: %ld", baseResult);
    LOGI("set_sym_key phKey: %s", bKeyHandle);
    (*env)->ReleaseByteArrayElements(env, str_, bBuffer, 0);
    return baseResult;
}

JNIEXPORT jstring JNICALL get_sym_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("get_sym_key handle: %ld", handle);
    char phKey[SIZE_BUFFER_32];
    unsigned long baseResult = 1;//SKF_GetSymmKey( handle, SGD_SM2_1, phKey );
    LOGI("get_sym_key baseResult: %ld", baseResult);
    LOGI("get_sym_key phKey: %s", phKey);
    jstring  result = charToJstring(env, phKey);
    return result;
}

JNIEXPORT jlong JNICALL check_sym_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("check_sym_key handle: %ld", handle);
    unsigned long phKey;
    unsigned long baseResult = 1;//SKF_CheckSymmKey( handle, SGD_SM2_1, &phKey );
    LOGI("check_sym_key baseResult: %ld", baseResult);
    LOGI("check_sym_key phKey: %ld", phKey);
    return phKey;
}

JNIEXPORT jlong JNICALL close_handle(JNIEnv *env, jobject instance, jint handle) {
    LOGI("close_handle handle: %ld", handle);
    unsigned long baseResult = SKF_CloseHandle( handle );
    LOGI("close_handle baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jstring JNICALL get_dev_info(JNIEnv *env, jobject instance, jint handle) {
    LOGI("get_dev_info handle: %ld", handle);
    DEVINFO devInfo = {0};
    unsigned long baseResult = SKF_GetDevInfo( handle, &devInfo );
    LOGI("get_dev_info baseResult: %ld", baseResult);
    LOGI("get_dev_info devInfo.Label: %s\n", devInfo.Label);
    LOGI("get_dev_info devInfo.Issuer: %s\n", devInfo.Issuer);
    LOGI("get_dev_info devInfo.Manufacturer: %s\n", devInfo.Manufacturer);
    LOGI("get_dev_info devInfo.SerialNumber: %s\n", devInfo.SerialNumber);
//    ShowDeviceInfo(&devInfo);
    jstring  result = charToJstring(env, devInfo.Label);
    return result;
}

JNIEXPORT jlong JNICALL get_za(JNIEnv *env, jobject instance, jint handle, jbyteArray str_) {
    LOGI("get_za handle: %ld", handle);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    LOGI("get_za pbCommand: %s\n", pbCommand);
    LOGI("get_za pbCommand size: %d\n", strlen(pbCommand));
    if (pbCommand == NULL) {
        LOGE("transmit_ex with null string.");
        return -1;
    }
    BYTE pbZAData[64];
    ULONG pulZALen;
    unsigned long baseResult = 1;//V_GetZA( handle, pbCommand, pbZAData, &pulZALen );
    LOGI("get_za baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_init handle: %ld", handle);
    BLOCKCIPHERPARAM EncryptParam;
    EncryptParam.IVLen = 0;
    EncryptParam.PaddingType = 0;
    unsigned long baseResult = SKF_EncryptInit( bKeyHandle, EncryptParam );
    LOGI("encrypt_init baseResult: %ld", baseResult);
    LOGI("encrypt_init baseResult: %ld", EncryptParam.IVLen);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL encrypt(JNIEnv *env, jobject instance, jint handle, jbyteArray str_) {
    LOGI("encrypt handle: %ld", handle);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbData = (unsigned char*) bBuffer;
    LOGI("encrypt pbData: %s\n", pbData);
    LOGI("encrypt pbData size: %d\n", strlen(pbData));
    if (pbData == NULL) {
        LOGE("encrypt with null string.");
        return -1;
    }
    ULONG ulDataLen = strlen(pbData);
    BYTE pbOutData[4096] = { 0 };
    unsigned long pulCertLen = sizeof (pbOutData) / sizeof (BYTE);
    unsigned long baseResult = SKF_Encrypt( handle, pbData, ulDataLen, pbOutData, &pulCertLen );
    LOGI("encrypt result: %ld", baseResult);
    LOGI("encrypt pulCertLen: %ld", pulCertLen);
    LOGI("encrypt pbOutData: %s", pbOutData);
    (*env)->ReleaseByteArrayElements(env, str_, bBuffer, 0);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    jbyte *by = (jbyte*) pbOutData;
    jbyteArray retArray = (*env)->NewByteArray(env, pulCertLen);
    (*env)->SetByteArrayRegion(env, retArray, 0, pulCertLen, by);
    // need free the memory
    free(pbOutData);
    return retArray;
}

JNIEXPORT jlong JNICALL encrypt_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_EncryptUpdate( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("encrypt_update baseResult: %ld", baseResult);
    // next is the en/de crypt test
//    cipher_one_test(pbData, "SM1_ECB", SGD_SM1_ECB);
    return baseResult;
}

JNIEXPORT jlong JNICALL encrypt_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("encrypt_final handle: %ld", handle);
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_EncryptFinal( handle, pbEncryptedData, pulEncryptedLen );
    LOGI("encrypt_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_init handle: %ld", handle);
    BLOCKCIPHERPARAM encryptParam;
    unsigned long baseResult = SKF_DecryptInit( handle, encryptParam );
    LOGI("decrypt_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Decrypt( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_DecryptUpdate( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL decrypt_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("decrypt_final handle: %ld", handle);
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_DecryptFinal( handle, pbEncryptedData, pulEncryptedLen );
    LOGI("decrypt_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_init handle: %ld", handle);
    ECCPUBLICKEYBLOB* pPubKey;
    BYTE* pucID;
    ULONG ulIDLen;
    HANDLE *phHash;
    unsigned long baseResult = SKF_DigestInit( handle, SGD_SM2_1, pPubKey, pucID, ulIDLen, phHash );
    LOGI("digest_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Digest( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("digest baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    unsigned long baseResult = SKF_DigestUpdate( handle, pbData, ulDataLen );
    LOGI("digest_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL digest_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("digest_final handle: %ld", handle);
    BYTE *pbHashData;
    ULONG *pulHashLen;
    unsigned long baseResult = SKF_DigestFinal( handle, pbHashData, pulHashLen );
    LOGI("digest_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_init(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_init handle: %ld", handle);
    BLOCKCIPHERPARAM* pMacParam;
    HANDLE *phMac;
    unsigned long baseResult = SKF_MacInit( handle, pMacParam, phMac );
    LOGI("mac_init baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbEncryptedData;
    ULONG *pulEncryptedLen;
    unsigned long baseResult = SKF_Mac( handle, pbData, ulDataLen, pbEncryptedData, pulEncryptedLen );
    LOGI("mac baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_update(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_update handle: %ld", handle);
    BYTE *pbData;
    ULONG ulDataLen;
    unsigned long baseResult = SKF_MacUpdate( handle, pbData, ulDataLen );
    LOGI("mac_update baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL mac_final(JNIEnv *env, jobject instance, jint handle) {
    LOGI("mac_final handle: %ld", handle);
    BYTE *pbHashData;
    ULONG *pulHashLen;
    unsigned long baseResult = SKF_MacFinal( handle, pbHashData, pulHashLen );
    LOGI("mac_final baseResult: %ld", baseResult);
    return baseResult;
}

JNIEXPORT jlong JNICALL gen_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("generate_key handle: %ld", handle);
    unsigned char *pbOutData = (char *) malloc(SIZE_BUFFER_32 * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("export_cert with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SIZE_BUFFER_32 * sizeof(char));
    unsigned long pDataLen = 0;
    unsigned long baseResult = 1;//V_GenerateKey( handle, SGD_SM1, apdu_A001, pbOutData, &pDataLen );
    memcpy(KEY_HANDLE, pbOutData, pDataLen);
    LOGI("generate_key baseResult: %ld", baseResult);
    LOGI("generate_key pbOutData: %s\n", pbOutData);
    free(pbOutData);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_export_session_key(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_export_session_key handle: %ld", handle);
    unsigned char *pbOutData = (char *) malloc(SIZE_BUFFER_32 * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("export_cert with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SIZE_BUFFER_32 * sizeof(char));
    unsigned long pDataLen = 0;
    unsigned long baseResult = 1;//V_ECCExportSessionKeyByHandle( handle, apdu_A001, KEY_HANDLE, SIZE_BUFFER_32, pbOutData, &pDataLen );
    LOGI("ecc_export_session_key baseResult: %ld", baseResult);
    LOGI("ecc_export_session_key pbOutData: %s\n", pbOutData);
    free(pbOutData);
    return baseResult;
}

JNIEXPORT jlong JNICALL ecc_prv_key_decrypt(JNIEnv *env, jobject instance, jint handle) {
    LOGI("ecc_prv_key_decrypt handle: %ld", handle);
    unsigned char *pbOutData = (char *) malloc(SIZE_BUFFER_32 * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("export_cert with null alloc.");
        return NULL;
    }
    memset(pbOutData, 0x00, SIZE_BUFFER_32 * sizeof(char));
    unsigned long pDataLen = 0;
    BYTE pbPlainText[SIZE_BUFFER_512];
    unsigned long baseResult = V_ECCPrvKeyDecrypt( handle, apdu_A001, pbPlainText, pbOutData, &pDataLen );
    LOGI("ecc_prv_key_decrypt baseResult: %ld", baseResult);
    LOGI("ecc_prv_key_decrypt pbOutData: %s\n", pbOutData);
    return baseResult;
}

JNIEXPORT jlong JNICALL import_key_pair(JNIEnv *env, jobject instance, jint handle) {
    LOGI("import_key_pair handle: %ld", handle);
    unsigned char *pubKey = (unsigned char *) malloc(SIZE_BUFFER_64 * sizeof(char));
    if (pubKey == NULL) {
        LOGE("import_ecc_key with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(pubKey, '0x06', SIZE_BUFFER_64 * sizeof(char));
    unsigned char *privKey = (unsigned char *) malloc(SIZE_BUFFER_32 * sizeof(char));
    if (privKey == NULL) {
        LOGE("import_ecc_key with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(privKey, '0x05', SIZE_BUFFER_32 * sizeof(char));
    unsigned long baseResult = V_ImportKeyPair( handle, apdu_A001, pubKey, privKey );
    LOGI("ecc_export_session_key baseResult: %ld", baseResult);
    free(pubKey);
    free(privKey);
    return baseResult;
}

JNIEXPORT jlong JNICALL cipher(JNIEnv *env, jobject instance, jint handle) {
    LOGI("cipher handle: %ld", handle);
    // need update Cipher
    BYTE *pbData;
    ULONG ulDataLen;
    BYTE *pbSignature;
    ULONG *pulSignLen;
    unsigned long baseResult = V_Cipher(handle, pbData, ulDataLen, pbSignature, pulSignLen);
    LOGI("ecc_sign_data baseResult: %ld", baseResult);
    return baseResult;
}

// Java和JNI函数的绑定表
static JNINativeMethod method_table[] = {
        {"setPackageName",  "(Ljava/lang/String;)J",                                   (void *) set_package},
        {"GetFuncList",     "()Ljava/lang/String;",                                    (void *) get_func_list},
        {"ImportCert",      "(I[B)J",                                                  (void *) import_cert},
        {"ExportCert",      "(I)[B",                                                   (void *) export_cert},
        {"EnumDev",         "()Ljava/lang/String;",                                    (void *) enum_dev},
        {"ConnectDev",      "(Ljava/lang/String;)I",                                   (void *) connect_dev},
        {"DisconnectDev",   "(I)J",                                                    (void *) disconnect_dev},
        {"GenRandom",       "(I)Ljava/lang/String;",                                   (void *) gen_random},
        {"GenECCKeyPair",   "(I)[B",                                                   (void *) gen_ecc_key},
        {"ImportECCKey",    "(I[B[B)J",                                                (void *) import_ecc_key},
        {"ECCSignData",     "(I[B)[B",                                                 (void *) ecc_sign_data},
        {"ECCVerify",       "(I[B[B)J",                                                (void *) ecc_verify},
        {"ExtECCVerify",    "(I)J",                                                    (void *) ext_ecc_verify},
        {"GenDataWithECC",   "(I)J",                                                    (void *) gen_data_ecc},
        {"GenKeyWithECC",    "(I)J",                                                    (void *) gen_key_ecc},
        {"GenDataAndKeyWithECC", "(I)J",                                                (void *) gen_data_key_ecc},
        {"ExportPublicKey",   "(I)[B",                                                  (void *) export_public_key},
        {"ImportSessionKey",  "(I)J",                                                   (void *) import_session_key},
        {"SetSymKey",         "(I[B)J",                                                 (void *) set_sym_key},
        {"GetSymKey",         "(I)Ljava/lang/String;",                                  (void *) get_sym_key},
        {"CheckSymKey",       "(I)J",                                                   (void *) check_sym_key},
        {"CloseHandle",       "(I)J",                                                   (void *) close_handle},
        {"GetDevInfo",        "(I)Ljava/lang/String;",                                  (void *) get_dev_info},
        {"GetZA",             "(I[B)J",                                                 (void *) get_za},
        {"EncryptInit",       "(I)J",                                                   (void *) encrypt_init},
        {"Encrypt",           "(I[B)[B",                                                (void *) encrypt},
        {"EncryptUpdate",     "(I)J",                                                   (void *) encrypt_update},
        {"EncryptFinal",      "(I)J",                                                   (void *) encrypt_final},
        {"DecryptInit",       "(I)J",                                                   (void *) decrypt_init},
        {"Decrypt",           "(I)J",                                                   (void *) decrypt},
        {"DecryptUpdate",     "(I)J",                                                   (void *) decrypt_update},
        {"DecryptFinal",      "(I)J",                                                   (void *) decrypt_final},
        {"DigestInit",        "(I)J",                                                   (void *) digest_init},
        {"Digest",            "(I)J",                                                   (void *) digest},
        {"DigestUpdate",      "(I)J",                                                   (void *) digest_update},
        {"DigestFinal",       "(I)J",                                                   (void *) digest_final},
        {"MacInit",           "(I)J",                                                   (void *) mac_init},
        {"MacUpdate",         "(I)J",                                                   (void *) mac_update},
        {"MacFinal",          "(I)J",                                                   (void *) mac_final},
        {"GenerateKey",       "(I)J",                                                   (void *) gen_key},
        {"ECCExportSessionKey", "(I)J",                                                 (void *) ecc_export_session_key},
        {"ECCPrvKeyDecrypt",  "(I)J",                                                   (void *) ecc_prv_key_decrypt},
        {"ImportKeyPair",     "(I)J",                                                   (void *) import_key_pair},
        {"Cipher",            "(I)J",                                                   (void *) cipher},
};

// 注册native方法到java中
static int registerNativeMethods(JNIEnv *env, const char *className,
                                 JNINativeMethod *gMethods, int numMethods) {
    jclass clazz;
    clazz = (*env)->FindClass(env, className);
    if (clazz == NULL) {
        return JNI_FALSE;
    }
    if ((*env)->RegisterNatives(env, clazz, gMethods, numMethods) < 0) {
        return JNI_FALSE;
    }

    return JNI_TRUE;
}

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {

//    ptrace(PTRACE_TRACEME, 0, 0, 0);

    JNIEnv *env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }

    // call register method
    if (registerNativeMethods(env, JNIREG_CLASS, method_table, NELEM(method_table)) <= 0) {
        return result;
    }

    // return jni version
    return JNI_VERSION_1_4;
}

