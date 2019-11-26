#include <jni.h>
#include <string.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include "aes.h"
#include "checksignature.h"
#include "check_emulator.h"
#include "logger.h"
#include "SDKey.h"

#define CBC 1
#define ECB 1

// 获取数组的大小
# define NELEM(x) ((int) (sizeof(x) / sizeof((x)[0])))
// 指定要注册的类，对应完整的java类名
#define JNIREG_CLASS "com/tongxin/sdjni/SdEncrypt"

const char *UNSIGNATURE = "UNSIGNATURE";

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

//__attribute__((section (".mytext")))//隐藏字符表 并没有什么卵用 只是针对初阶hacker的一个小方案而已
char *getKey() {
    int n = 0;
    char s[23];//"NMTIzNDU2Nzg5MGFiY2RlZg";

    s[n++] = 'N';
    s[n++] = 'M';
    s[n++] = 'T';
    s[n++] = 'I';
    s[n++] = 'z';
    s[n++] = 'N';
    s[n++] = 'D';
    s[n++] = 'U';
    s[n++] = '2';
    s[n++] = 'N';
    s[n++] = 'z';
    s[n++] = 'g';
    s[n++] = '5';
    s[n++] = 'M';
    s[n++] = 'G';
    s[n++] = 'F';
    s[n++] = 'i';
    s[n++] = 'Y';
    s[n++] = '2';
    s[n++] = 'R';
    s[n++] = 'l';
    s[n++] = 'Z';
    s[n++] = 'g';
    char *encode_str = s + 1;
    return b64_decode(encode_str, strlen(encode_str));

}

JNIEXPORT jstring JNICALL encode(JNIEnv *env, jobject instance, jobject context, jstring str_) {

    //先进行apk被 二次打包的校验
    if (check_signature(env, instance, context) != 1 || check_is_emulator(env) != 1) {
        char *str = (char *) UNSIGNATURE;
//        return (*env)->NewString(env, str, strlen(str));
        return charToJstring(env,str);
    }

    uint8_t *AES_KEY = (uint8_t *) getKey();
    const char *in = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    char *baseResult = AES_128_ECB_PKCS5Padding_Encrypt(in, AES_KEY);
    (*env)->ReleaseStringUTFChars(env, str_, in);
//    return (*env)->NewStringUTF(env, baseResult);
    jstring  result = (*env)->NewStringUTF(env, baseResult);
    free(baseResult);
    free(AES_KEY);
    return result;
}


JNIEXPORT jstring JNICALL decode(JNIEnv *env, jobject instance, jobject context, jstring str_) {


    //先进行apk被 二次打包的校验
    if (check_signature(env, instance, context) != 1|| check_is_emulator(env) != 1) {
        char *str = (char *) UNSIGNATURE;
//        return (*env)->NewString(env, str, strlen(str));
        return charToJstring(env,str);
    }

    uint8_t *AES_KEY = (uint8_t *) getKey();
    const char *str = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    char *desResult = AES_128_ECB_PKCS5Padding_Decrypt(str, AES_KEY);
    (*env)->ReleaseStringUTFChars(env, str_, str);
//    return (*env)->NewStringUTF(env, desResult);
    //不用系统自带的方法NewStringUTF是因为如果desResult是乱码,会抛出异常
//    return charToJstring(env,desResult);
    jstring result = charToJstring(env,desResult);
    free(desResult);
    free(AES_KEY);
    return result;
}

/**
 * if rerurn 1 ,is check pass.
 */
JNIEXPORT jint JNICALL
check_jni(JNIEnv *env, jobject instance, jobject con) {
    return check_signature(env, instance, con);
}

JNIEXPORT jstring JNICALL get_version(JNIEnv *env, jobject instance) {
    char *firmVer = (char *) malloc(VERSION_NAME_LEN * sizeof(char));
    if (firmVer == NULL) {
        LOGE("get_firm_ver with null alloc.");
        return (*env)->NewStringUTF(env, '\0');
    }
    memset(firmVer, 0x00, VERSION_NAME_LEN * sizeof(char));
    int baseResult = GetVersion(firmVer);
    LOGI("get_firm_ver baseResult: %d", baseResult);
    jstring  result = charToJstring(env, firmVer);
    // need free the memory
    free(firmVer);
    return result;
}

JNIEXPORT jint JNICALL input_key(JNIEnv *env, jobject instance, jbyteArray str_, jint offset, jint length) {
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("input_key with null string.");
        return -1;
    }
    int baseResult = InputKey(pbCommand, offset, length);
    LOGI("input_key baseResult: %d", baseResult);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL read_key(JNIEnv *env, jobject instance, jint offset, jint length) {
    unsigned char *pbOutData = (unsigned char *) malloc(length * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("read_key malloc with null.");
        return NULL;
    }
    memset(pbOutData, '\0', length * sizeof(char));
    int baseResult = ReadKey(pbOutData, offset, length);
    LOGI("read_key baseResult: %d", baseResult);
    jbyte *by = (jbyte*)pbOutData;
    jbyteArray result = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, result, 0, length, by);
    // need free the memory
    free(pbOutData);
    return result;
}

JNIEXPORT jbyteArray JNICALL transmit_data(JNIEnv *env, jobject instance, jbyteArray str_, jint length, jint outLen) {
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    char* pbCommand = (char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("transmit_data with null string.");
        return NULL;
    }
//    char *pbOutData = (char *) malloc(outLen * sizeof(char));
//    if (pbOutData == NULL) {
//        LOGE("transmit_data with null alloc.");
//        return NULL;
//    }
    LOGD("TransmitData getpagesize page size = %d\n", getpagesize());
    unsigned char* pbOutData = memalign(getpagesize(), outLen);
    if (pbOutData == NULL) {
//        perror("posix_memalign error");
        LOGE("TransmitData memalign error. \n");
        return NULL;
    }
    memset(pbOutData, '\0', outLen * sizeof(char));
    int baseResult = TransmitData(pbCommand, length, pbOutData, outLen);
    LOGI("transmit_data baseResult: %d", baseResult);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    LOGI("transmit_data pbOutData: %s\n", pbOutData);
    jbyte *by = (jbyte*)pbOutData;
    jbyteArray jarray = (*env)->NewByteArray(env, outLen);
    (*env)->SetByteArrayRegion(env, jarray, 0, outLen, by);
    // need free the memory
    free(pbOutData);
    return jarray;
}

JNIEXPORT jstring JNICALL read_key1(JNIEnv *env, jobject instance, jstring file, jint offset, jint length) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("read_key1 file path: %s\n", str);
    char *pbOutData = (char *) malloc(length * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("read_key1 malloc with null.");
        return NULL;
    }
    memset(pbOutData, '\0', length * sizeof(char));
    int baseResult = ReadKey1(str, pbOutData, offset, length);
    LOGI("read_key1 baseResult: %d", baseResult);
    jstring  result = charToJstring(env, pbOutData);
    // need free the memory
    free(pbOutData);
    return result;
}

JNIEXPORT jint JNICALL input_key1(JNIEnv *env, jobject instance, jstring file, jstring str_, jint offset, jint length) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("input_key1 file path: %s\n", str);
    const char *bBuffer = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    LOGI("input_key1 file bBuffer: %s\n", bBuffer);
    int baseResult = InputKey1(str, bBuffer, offset, length);
    LOGI("input_key1 baseResult: %d", baseResult);
    return baseResult;
}

JNIEXPORT jstring JNICALL transmit_data1(JNIEnv *env, jobject instance, jstring file, jstring str_, jint length, jint outLen) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("transmit_data1 file path: %s\n", str);
    const char *bBuffer = (*env)->GetStringUTFChars(env, str_, JNI_FALSE);
    LOGI("transmit_data1 file bBuffer: %s\n", bBuffer);
    char *pbOutData = (char *) malloc(outLen * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("transmit_data1 with null alloc.");
        return NULL;
    }
    memset(pbOutData, '\0', outLen * sizeof(char));
    int baseResult = TransmitData1(str, bBuffer, length, pbOutData, outLen);
    LOGI("transmit_data1 baseResult: %d", baseResult);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    jstring  result = charToJstring(env, pbOutData);
    // need free the memory
    free(pbOutData);
    return result;
}

JNIEXPORT jbyteArray JNICALL read_key2(JNIEnv *env, jobject instance, jstring file, jint offset, jint length) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("read_key2 file path: %s\n", str);
    unsigned char *pbOutData = (unsigned char *) malloc(length * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("read_key2 malloc with null.");
        return NULL;
    }
    memset(pbOutData, '\0', length * sizeof(char));
    int baseResult = ReadKey2(str, pbOutData, offset, length);
    LOGI("read_key2 baseResult: %d", baseResult);
    jbyte *by = (jbyte*)pbOutData;
    jbyteArray jarray = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, jarray, 0, length, by);
    // need free the memory
    free(pbOutData);
    return jarray;
}

JNIEXPORT jint JNICALL input_key2(JNIEnv *env, jobject instance, jstring file, jbyteArray str_, jint offset, jint length) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("input_key2 file path: %s\n", str);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("input_key2 with null string.");
        return -1;
    }
    int baseResult = InputKey2(str, pbCommand, offset, length);
    LOGI("input_key2 baseResult: %d", baseResult);
    return baseResult;
}

JNIEXPORT jbyteArray JNICALL transmit_data2(JNIEnv *env, jobject instance, jstring file, jbyteArray str_, jint length, jint outLen) {
    const char *str = (*env)->GetStringUTFChars(env, file, JNI_FALSE);
    LOGI("transmit_data2 file path: %s\n", str);
    jbyte* bBuffer = (*env)->GetByteArrayElements(env, str_, 0);
    unsigned char* pbCommand = (unsigned char*) bBuffer;
    if (pbCommand == NULL) {
        LOGE("transmit_data2 with null string.");
        return NULL;
    }
    unsigned char *pbOutData = (unsigned char *) malloc(outLen * sizeof(char));
    if (pbOutData == NULL) {
        LOGE("transmit_data2 with null alloc.");
        return NULL;
    }
    memset(pbOutData, '\0', outLen * sizeof(char));
    int baseResult = TransmitData2(str, pbCommand, length, pbOutData, outLen);
    LOGI("transmit_data2 baseResult: %d", baseResult);
    if (baseResult != 0) {
        free(pbOutData);
        return NULL;
    }
    LOGI("transmit_data2 pbOutData: %s\n", pbOutData);
    jbyte *by = (jbyte*)pbOutData;
    jbyteArray jarray = (*env)->NewByteArray(env, outLen);
    (*env)->SetByteArrayRegion(env, jarray, 0, outLen, by);
    // need free the memory
    free(pbOutData);
    return jarray;
}

// Java和JNI函数的绑定表
static JNINativeMethod method_table[] = {
        {"checkSignature", "(Ljava/lang/Object;)I",                                    (void *) check_jni},
        {"decode",         "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;", (void *) decode},
        {"encode",         "(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;", (void *) encode},
        {"getver",         "()Ljava/lang/String;",                                            (void *) get_version},
        {"inputkey",       "([BII)I",                                                         (void *) input_key},
        {"readkey",        "(II)[B",                                                          (void *) read_key},
        {"transmitdata",   "([BII)[B",                                                        (void *) transmit_data},
        {"getver",         "()Ljava/lang/String;",                                            (void *) get_version},
        {"inputkey1",       "(Ljava/lang/String;Ljava/lang/String;II)I",                      (void *) input_key1},
        {"readkey1",        "(Ljava/lang/String;II)Ljava/lang/String;",                        (void *) read_key1},
        {"transmitdata1",   "(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;",      (void *) transmit_data1},
        {"inputkey2",       "(Ljava/lang/String;[BII)I",                                       (void *) input_key2},
        {"readkey2",        "(Ljava/lang/String;II)[B",                                        (void *) read_key2},
        {"transmitdata2",   "(Ljava/lang/String;[BII)[B",                                      (void *) transmit_data2}
};

// 注册native方法到java中
static int registerNativeMethods(JNIEnv *env, const char *className, JNINativeMethod *gMethods, int numMethods) {
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
    ptrace(PTRACE_TRACEME, 0, 0, 0);//反调试
//这是一种比较简单的防止被调试的方案
// 有更复杂更高明的方案，比如：不用这个ptrace而是每次执行加密解密签先去判断是否被trace,目前的版本不做更多的负载方案，您想做可以fork之后，自己去做

    JNIEnv *env = NULL;
    jint result = -1;

    if ((*vm)->GetEnv(vm, (void **) &env, JNI_VERSION_1_4) != JNI_OK) {
        return result;
    }

    // 调用注册方法
    result = registerNativeMethods(env, JNIREG_CLASS, method_table, NELEM(method_table));
    if (result != JNI_TRUE) {
        LOGE("Failed to register Native Methods. \n");
    }

    return JNI_VERSION_1_4;
}

