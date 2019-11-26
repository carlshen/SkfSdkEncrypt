package com.tongxin.sdencrypt;

import android.content.Context;
import android.os.Build;
import android.os.Environment;
import android.os.StatFs;
import android.os.storage.StorageManager;
import android.support.v4.os.EnvironmentCompat;
import android.util.Log;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.lang.reflect.Array;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.ArrayList;

/**
 * Project： ZGBackup
 * File: StorageUtils.java
 */

public class StorageUtils {
    private static final String TAG = StorageUtils.class.getSimpleName();

    public static String EXTERNAL_SDCARD = "/storage/9016-4EE8";
    public static String EXTERNAL_PATH = "/Android/data/com.tongxin.sdencrypt";
    /**
     * 获取存储卡跟目录
     *
     * @param context
     * @return 优先返回 SD 卡根目录，没有 SD 卡则返回内置卡的跟目录
     */
    public static String getSuggestStoragePath(Context context) {
        StorageManager mStorageManager = (StorageManager) context.getSystemService(Context.STORAGE_SERVICE);
        Class<?> storageVolumeClazz;
        try {
            storageVolumeClazz = Class.forName("android.os.storage.StorageVolume");
            Method getVolumeList = mStorageManager.getClass().getMethod("getVolumeList");
            Method getVolumeData = storageVolumeClazz.getMethod("getPath");
            Object result = getVolumeList.invoke(mStorageManager);
            final int length = Array.getLength(result);
            Object internalRootPath = Array.get(result, length == 2 ? 1 : 0);
            Object internal = getVolumeData.invoke(internalRootPath);
            return (String) internal;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String readString(String targetAbsolutePath) {
        String str = "";
        File file = new File(targetAbsolutePath);
        FileInputStream in = null;
        try {
            in = new FileInputStream(file);
            int size = in.available();
            byte[] buffer = new byte[size];
            in.read(buffer);
            str = new String(buffer);
        } catch (IOException e) {
            return "";
        } finally {
            //CID 27520
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return str;
    }

    public static boolean writeString(String targetFolder, String targetFileName, String json) {
        Log.d(TAG, ".writeString() targetFolder " + targetFolder);
        Log.d(TAG, ".writeString() targetFileName " + targetFileName);
        Log.d(TAG, ".writeString() json " + json);
        File folder = new File(targetFolder);
        File file = new File(targetFolder, targetFileName);
        try {
            if (!folder.exists()) {
                boolean dir = folder.mkdirs();
                Log.d(TAG, ".writeString() mkdirs = " + dir);
            }
            if (file.exists()) {
                Log.d(TAG, ".writeString() destroy origin file");
                file.delete();
            }
            file.createNewFile();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        byte bt[] = json.getBytes();
        FileOutputStream in = null;
        try {
            in = new FileOutputStream(file);
            in.write(bt, 0, bt.length);
            in.flush();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return false;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } finally {
            //CID 27525
            if (null != in) {
                try {
                    in.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return true;
    }

    public static ArrayList<StorageBean> getStorageData(Context pContext) {
        final StorageManager storageManager = (StorageManager) pContext.getSystemService(Context.STORAGE_SERVICE);
        try {
            //得到StorageManager中的getVolumeList()方法的对象
            final Method getVolumeList = storageManager.getClass().getMethod("getVolumeList");
            //---------------------------------------------------------------------
            //得到StorageVolume类的对象
            final Class<?> storageValumeClazz = Class.forName("android.os.storage.StorageVolume");
            //---------------------------------------------------------------------
            //获得StorageVolume中的一些方法
            final Method getPath = storageValumeClazz.getMethod("getPath");
            Method isRemovable = storageValumeClazz.getMethod("isRemovable");

            Method mGetState = null;
            //getState 方法是在4.4_r1之后的版本加的，之前版本（含4.4_r1）没有
            // （http://grepcode.com/file/repository.grepcode.com/java/ext/com.google.android/android/4.4_r1/android/os/Environment.java/）
            if (Build.VERSION.SDK_INT > Build.VERSION_CODES.KITKAT) {
                try {
                    mGetState = storageValumeClazz.getMethod("getState");
                } catch (NoSuchMethodException e) {
                    e.printStackTrace();
                }
            }
            //---------------------------------------------------------------------

            //调用getVolumeList方法，参数为：“谁”中调用这个方法
            final Object invokeVolumeList = getVolumeList.invoke(storageManager);
            //---------------------------------------------------------------------
            final int length = Array.getLength(invokeVolumeList);
            ArrayList<StorageBean> list = new ArrayList<>();
            for (int i = 0; i < length; i++) {
                final Object storageValume = Array.get(invokeVolumeList, i);//得到StorageVolume对象
                final String path = (String) getPath.invoke(storageValume);
                final boolean removable = (Boolean) isRemovable.invoke(storageValume);
                String state;
                if (mGetState != null) {
                    state = (String) mGetState.invoke(storageValume);
                } else {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
                        state = Environment.getStorageState(new File(path));
                    } else {
                        if (removable) {
                            state = EnvironmentCompat.getStorageState(new File(path));
                        } else {
                            //不能移除的存储介质，一直是mounted
                            state = Environment.MEDIA_MOUNTED;
                        }
                        final File externalStorageDirectory = Environment.getExternalStorageDirectory();
                        Log.e(TAG, "externalStorageDirectory==" + externalStorageDirectory);
                    }
                }
                long totalSize = 0;
                long availaleSize = 0;
                if (Environment.MEDIA_MOUNTED.equals(state)) {
                    totalSize = StorageUtils.getTotalSize(path);
                    availaleSize = StorageUtils.getAvailableSize(path);
                }
                final String msg = "path==" + path
                        + " ,removable==" + removable
                        + ",state==" + state
                        + ",total size==" + totalSize + "(" + StorageUtils.fmtSpace(totalSize) + ")"
                        + ",availale size==" + availaleSize + "(" + StorageUtils.fmtSpace(availaleSize) + ")";
                Log.e(TAG, msg);
                StorageBean storageBean = new StorageBean();
                storageBean.setAvailableSize(availaleSize);
                storageBean.setTotalSize(totalSize);
                storageBean.setMounted(state);
                storageBean.setPath(path);
                storageBean.setRemovable(removable);
                list.add(storageBean);
            }
            return list;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static long getTotalSize(String path) {
        try {
            final StatFs statFs = new StatFs(path);
            long blockSize = 0;
            long blockCountLong = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                blockSize = statFs.getBlockSizeLong();
                blockCountLong = statFs.getBlockCountLong();
            } else {
                blockSize = statFs.getBlockSize();
                blockCountLong = statFs.getBlockCount();
            }
            return blockSize * blockCountLong;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public static long getAvailableSize(String path) {
        try {
            final StatFs statFs = new StatFs(path);
            long blockSize = 0;
            long availableBlocks = 0;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.JELLY_BEAN_MR2) {
                blockSize = statFs.getBlockSizeLong();
                availableBlocks = statFs.getAvailableBlocksLong();
            } else {
                blockSize = statFs.getBlockSize();
                availableBlocks = statFs.getAvailableBlocks();
            }
            return availableBlocks * blockSize;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    public static final long A_GB = 1073741824;
    public static final long A_MB = 1048576;
    public static final int A_KB = 1024;

    public static String fmtSpace(long space) {
        if (space <= 0) {
            return "0";
        }
        double gbValue = (double) space / A_GB;
        if (gbValue >= 1) {
            return String.format("%.2fGB", gbValue);
        } else {
            double mbValue = (double) space / A_MB;
            Log.e("GB", "gbvalue=" + mbValue);
            if (mbValue >= 1) {
                return String.format("%.2fMB", mbValue);
            } else {
                final double kbValue = space / A_KB;
                return String.format("%.2fKB", kbValue);
            }
        }
    }
}
