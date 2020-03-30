package com.tongxin.sdencrypt;

import android.content.Context;
import android.os.Environment;
import android.util.Log;

import java.io.File;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;

/**
 * Created by carl on 2019/12/9.
 */
public class EncryptUtil {

    public static final String ALGORITHM_NAME_ECB_PADDING = "SM4/ECB/PKCS5Padding";
    public static final String ENCODING = "UTF-8";
    public static final String ALGORITHM_NAME = "AES";
    public static final int DEFAULT_KEY_SIZE = 128;
    public static final String DEVICE_NAME = "DEVICE_NAME";
    public static final String SYMKEY_HANDLE = "SYMKEY_HANDLE";
    public static final String KEY_HANDLE = "KEY_HANDLE";

    /**
     * 自动生成密钥
     * @return byte[]
     * @throws Exception
     */
    public static byte[] generateKey() throws Exception {
        return generateKey(DEFAULT_KEY_SIZE);
    }

    /**
     * @param keySize
     * @return byte[]
     * @throws Exception
     */
    public static byte[] generateKey(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME);
        kg.init(keySize, new SecureRandom());
        return kg.generateKey().getEncoded();
    }
    public static byte[] generateInterface(int keySize) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance(ALGORITHM_NAME);
        kg.init(keySize, new SecureRandom());
        java.security.Security ss;
        java.security.interfaces.DSAKey key;
        PublicKey kkkk;
        SecretKeySpec sssk;
//        Hex.encodeHash().matches();
        MessageDigest md = MessageDigest.getInstance(ALGORITHM_NAME);
        return kg.generateKey().getEncoded();
    }

    public static boolean SKF_Exist(Context context) {
        if (context == null) {
            Log.e("EncryptUtil", "SKF_Exist parameter is null.");
            return false;
        }
        ArrayList<StorageBean> gg = StorageUtils.getStorageData(context);
        for (StorageBean bean: gg) {
            if (!bean.getPath().toLowerCase().contains("private") && !bean.getPath().toLowerCase().contains("emulated")) {
                StorageUtils.EXTERNAL_SDCARD = bean.getPath();
                return true;
            }
        }
        return false;
    }

    public static String ByteArrayToHexString(byte[] bytes) {
        final char[] hexArray = {'0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'};
        char[] hexChars = new char[bytes.length * 2]; // Each byte has two hex characters (nibbles)
        int v;
        for (int j = 0; j < bytes.length; j++) {
            v = bytes[j] & 0xFF; // Cast bytes[j] to int, treating as unsigned value
            hexChars[j * 2] = hexArray[v >>> 4]; // Select hex character from upper nibble
            hexChars[j * 2 + 1] = hexArray[v & 0x0F]; // Select hex character from lower nibble
        }
        return new String(hexChars);
    }

    public static byte[] HexStringToByteArray(String s) throws IllegalArgumentException {
        int len = s.length();
        if (len % 2 == 1) {
            throw new IllegalArgumentException("Hex string must have even number of characters");
        }
        byte[] data = new byte[len / 2]; // Allocate 1 byte per 2 hex characters
        for (int i = 0; i < len; i += 2) {
            // Convert each character into a integer (base-16), then bit-shift into place
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    private static boolean isExternalStorageDisable() {
        return !Environment.MEDIA_MOUNTED.equals(Environment.getExternalStorageState());
    }

    private static String getAbsolutePath(final File file) {
        if (file == null) return "";
        return file.getAbsolutePath();
    }

    /**
     * Return the path of /storage/emulated/0/Android/data/package/files.
     *
     * @return the path of /storage/emulated/0/Android/data/package/files
     */
    public static String getExternalAppFilesPath(Context context) {
        if (context == null) {
            return "";
        }
        if (isExternalStorageDisable()) return "";
        return getAbsolutePath(context.getExternalFilesDir(null));
    }

    /**
     * Return the path of /storage/emulated/0.
     *
     * @return the path of /storage/emulated/0
     */
    public static String getExternalStoragePath() {
        if (isExternalStorageDisable()) return "";
        return getAbsolutePath(Environment.getExternalStorageDirectory());
    }

}
