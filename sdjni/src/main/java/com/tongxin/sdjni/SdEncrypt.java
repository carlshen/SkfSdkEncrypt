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
     * AES加密
     *
     * @param context
     * @param str
     * @return
     */
    public static native String encode(Object context, String str);


    /**
     * AES 解密
     *
     * @param context
     * @param str
     * @return UNSIGNATURE ： sign not pass .
     */
    public static native String decode(Object context, String str);


    /**
     * 检查 打包签名是否 是正确的 防止被二次打包
     *
     * @param context
     * @return 1 : pass ， -1 or  -2 : error.
     */
    public static native int checkSignature(Object context);

    public native String getver();
    public native int inputkey(byte[] key, int offset, int length);
    public native byte[] readkey(int offset, int length);
    public native byte[] transmitdata(byte[] key, int keylen, int length);
    public native int inputkey1(String file, String key, int offset, int length);
    public native String readkey1(String file, int offset, int length);
    public native String transmitdata1(String file, String key, int keylen, int length);
    public native int inputkey2(String file, byte[]  key, int offset, int length);
    public native byte[] readkey2(String file, int offset, int length);
    public native byte[] transmitdata2(String file, byte[] key, int keylen, int length);

}
