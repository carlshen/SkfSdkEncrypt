package com.tongxin.sdjni;

/**
 * Created by carl on 19-11-21.
 *
 * Super SD card file operate interface
 */

public class SdEncrypt {

    private static SdEncrypt SdInstance = null;
    private SdEncrypt() {}

    public static SdEncrypt getSdInstance() {
        if (SdInstance == null) {
            synchronized (SdEncrypt.class) {
                if (SdInstance == null) {
                    SdInstance = new SdEncrypt();
                }
            }
        }
        return SdInstance;
    }

    static {
        System.loadLibrary("SDKey");
    }

    /**
     * set package name
     * @param str
     * @return 1 : pass ， -1 or  -2 : error.
     */
    public static native long setPackageName(String str);
    public static native String GetFuncList();
    public static native long ImportCert(int handle, byte[] command);
    public static native byte[] ExportCert(int handle);
    public static native String EnumDev();
    public static native int ConnectDev(String dev);
    public static native long DisconnectDev(int handle);
    // cipher management
    public static native String GenRandom(int handle);
    public static native byte[] GenECCKeyPair(int handle);
    public static native long ImportECCKey(int handle, byte[]pubkey, byte[]prvkey);
    public static native byte[] ECCSignData(int handle, byte[]data);
    public static native long ECCVerify(int handle, byte[]sign, byte[]data);
    public static native long ExtECCVerify(int handle);
    public static native long GenDataWithECC(int handle);
    public static native long GenKeyWithECC(int handle);
    public static native long GenDataAndKeyWithECC(int handle);
    public static native byte[] ExportPublicKey(int handle);
    public static native long ImportSessionKey(int handle);
    // cipher supplement service
    public static native long SetSymKey(int handle, byte[] key);
    public static native String GetSymKey(int handle);
    public static native long CheckSymKey(int handle);
    public static native long CloseHandle(int handle);
    public static native String GetDevInfo(int handle);
    public static native long GetZA(int handle, byte[] command);
    public static native long EncryptInit(int handle);
    public static native byte[] Encrypt(int handle, byte[] data);
    public static native long EncryptUpdate(int handle);
    public static native long EncryptFinal(int handle);
    public static native long DecryptInit(int handle);
    public static native long Decrypt(int handle);
    public static native long DecryptUpdate(int handle);
    public static native long DecryptFinal(int handle);
    public static native long DigestInit(int handle);
    public static native long Digest(int handle);
    public static native long DigestUpdate(int handle);
    public static native long DigestFinal(int handle);
    public static native long MacInit(int handle);
    public static native long MacUpdate(int handle);
    public static native long MacFinal(int handle);
    public static native long GenerateKey(int handle);
    public static native long ECCExportSessionKey(int handle);
    public static native long ECCPrvKeyDecrypt(int handle);
    public static native long ImportKeyPair(int handle);
    public static native long Cipher(int handle);

}
