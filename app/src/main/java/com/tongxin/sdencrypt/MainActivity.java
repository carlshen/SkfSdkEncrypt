package com.tongxin.sdencrypt;

import android.Manifest;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.support.v4.app.ActivityCompat;
import android.support.v4.content.ContextCompat;
import android.support.v7.app.AppCompatActivity;
import android.text.TextUtils;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.tongxin.sdjni.SdEncrypt;

import java.io.File;
import java.util.ArrayList;

/**
 * Created by carl on 20-02-06.
 *
 * 用于公司的项目验证。
 */
public class MainActivity extends AppCompatActivity {

    public static final String TAG = "MainActivity";
    private File appsDir;
    private String extPath;
    private TextView tvResult = null;
    private TextView tvLog = null;
    // device management
    private Button mEnumDev = null;
    private Button mConnectDev = null;
    private Button mDisconnectDev = null;
    // container management
    private Button mImportCert = null;
    private Button mExportCert = null;
    // device
    private Button mSetAppPath = null;
    private Button mGetFuncList = null;
    // cipher management
    private Button mGenRandom = null;
    private Button mGenECCKeyPair = null;
    private Button mImportECCKeyPair = null;
    private Button mECCSignData = null;
    private Button mECCVerify = null;
    private Button mGenerateDataWithECC = null;
    private Button mGenerateKeyWithECC = null;
    private Button mGenerateDataAndKeyWithECC = null;
    private Button mExportPublicKey = null;
    private Button mImportSessionKey = null;
    private Button mCloseHandle = null;
    private Button mGetDevInfo = null;
    private Button mGetZA = null;
    private Button mNextPage = null;
    private String mECCData = null;
    private String ECCKeyPair = null;
    private String deviceName = null;
    private int deviceHandle = -1;
    private String KeyData = null;
    private String EncrpytData = null;
    private String DecrpytData = null;
    private String mEccSignedData = null;
    private String ImportData = null;
    private String ExportData = null;
    private String RandomData = null;
    private String PublicKey = null;
    private String PrivateKey = null;
    private String KeyHandle = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tvResult = (TextView) findViewById(R.id.tv_result);
        tvLog = (TextView) findViewById(R.id.tv_log);
        mEnumDev = (Button) findViewById(R.id.btn_device);
        mEnumDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                deviceName = SdEncrypt.EnumDev();
                tvResult.setText("EnumDev: " + deviceName);
            }
        });
        mConnectDev = (Button) findViewById(R.id.btn_connect);
        mConnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(deviceName)) {
                    deviceName = StorageUtils.EXTERNAL_SDCARD;
                }
                deviceHandle = SdEncrypt.ConnectDev(deviceName);
                tvResult.setText("ConnectDev: " + deviceHandle);
            }
        });
        mDisconnectDev = (Button) findViewById(R.id.btn_disconnect);
        mDisconnectDev.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.DisconnectDev(deviceHandle);
                tvResult.setText("DisconnectDev: " + result);
            }
        });

        mImportCert = (Button) findViewById(R.id.btn_importcert);
        mImportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                ImportData = "308201fd308201a3a003020102020500c15b78e3300a06082a811ccf5501837530818f310b300906035504061302415531283026060355040a0c1f546865204c6567696f6e206f662074686520426f756e637920436173746c653112301006035504070c094d656c626f75726e653111300f06035504080c08566963746f726961312f302d06092a864886f70d0109011620666565646261636b2d63727970746f40626f756e6379636173746c652e6f7267301e170d3230303330393039353231325a170d3231303330393039353231325a303b3110300e06035504030c076265696a696e67310c300a060355040b0c03746d6331193017060355040a0c106170706c69636174696f6e20756e69743059301306072a8648ce3d020106082a811ccf5501822d03420004b2c5f9be02b7dab8d8312b0ac8fb30bbedc79bee51d19efd647d2dbbd6f5e9078ad7837eeddcec2718a691d3c6c0a5dad6c53976b23f39c131a3f37a6d20eb33a33f303d300c0603551d130101ff04023000301d0603551d0e04160414e6521695daeb2f90867d2bedc1c79ad26ca8ef7e300e0603551d0f0101ff040403020410300a06082a811ccf550183750348003045022067a4e516d63ed3070791bd44b4c4df373048ccdfa20693690874456c9914a3f9022100db4facae7435dd123bc5db20e7ca88aa33914fe2853ddc4a11d364d33eda4913";
                long result = SdEncrypt.ImportCert(deviceHandle, EncryptUtil.HexStringToByteArray(ImportData));
                tvResult.setText("ImportCert result: " + result);
            }
        });
        mExportCert = (Button) findViewById(R.id.btn_exportcert);
        mExportCert.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] result = SdEncrypt.ExportCert(deviceHandle);
                if (result != null) {
                    ExportData = EncryptUtil.ByteArrayToHexString(result);
                    tvLog.setText("ExportCert result: " + ExportData);
                    tvResult.setText("ExportCert result length: " + result.length);
                } else {
                    tvResult.setText("ExportCert result failed. ");
                }
            }
        });
        mSetAppPath = (Button) findViewById(R.id.btn_setpath);
        mSetAppPath.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                callTongfang();
                tvResult.setText("setPackageName: ok.");
            }
        });
        mGetFuncList = (Button) findViewById(R.id.btn_getfunc);
        mGetFuncList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = SdEncrypt.GetFuncList();
                tvLog.setText("GetFuncList: " + result);
            }
        });
        mGenRandom = (Button) findViewById(R.id.btn_genrandom);
        mGenRandom.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                RandomData = SdEncrypt.GenRandom(deviceHandle);
                tvResult.setText("GenRandom: " + RandomData);
            }
        });
        mGenECCKeyPair = (Button) findViewById(R.id.btn_genecckey);
        mGenECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // need get the result
                byte[] result = SdEncrypt.GenECCKeyPair(deviceHandle);
                if (result != null) {
                    ECCKeyPair = EncryptUtil.ByteArrayToHexString(result);
                }
                tvResult.setText("GenECCKeyPair: " + ECCKeyPair);
            }
        });
        mImportECCKeyPair = (Button) findViewById(R.id.btn_importecckey);
        mImportECCKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                PublicKey = "b2c5f9be02b7dab8d8312b0ac8fb30bbedc79bee51d19efd647d2dbbd6f5e9078ad7837eeddcec2718a691d3c6c0a5dad6c53976b23f39c131a3f37a6d20eb33";
//                PrivateKey = "b21255a97dcd3a6c1f657cf926db7c03309c1b9cdbe864f3040e06ead154c381";
                PublicKey = "078a94425d8f991402af39cfa894dd26f76a05fd9fffc078f558119371b5058519301543a61a8536ba659d897a48fde531e9d0926cd01617b9a04d6003ad7417";
                PrivateKey = "33c903d77414e33385b673bf1cd1593c272b57cfff9c5528153d1b685dfbdc3c";
                long result = SdEncrypt.ImportECCKey(deviceHandle, EncryptUtil.HexStringToByteArray(PublicKey), EncryptUtil.HexStringToByteArray(PrivateKey));
                tvResult.setText("ImportECCKey: " + result);
            }
        });
        mECCSignData = (Button) findViewById(R.id.btn_eccsigndata);
        mECCSignData.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                mECCData = encbuilder.toString();
                byte[] result = SdEncrypt.ECCSignData(deviceHandle, EncryptUtil.HexStringToByteArray(mECCData));
                if (result != null) {
                    mEccSignedData = EncryptUtil.ByteArrayToHexString(result);
                }
                tvResult.setText("ECCSignData: " + mEccSignedData);
            }
        });
        mECCVerify = (Button) findViewById(R.id.btn_eccverify);
        mECCVerify.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.ECCVerify(deviceHandle, EncryptUtil.HexStringToByteArray(mEccSignedData), EncryptUtil.HexStringToByteArray(mECCData));
                tvResult.setText("ECCVerify: " + result);
            }
        });
        mGenerateDataWithECC = (Button) findViewById(R.id.btn_gendatawithecc);
        mGenerateDataWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
                long result = SdEncrypt.GenDataWithECC(deviceHandle);
                tvResult.setText("GenDataWithECC: just holder. " + result);
            }
        });
        mGenerateKeyWithECC = (Button) findViewById(R.id.btn_genkeywithecc);
        mGenerateKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.GenKeyWithECC(deviceHandle);
                tvResult.setText("GenKeyWithECC: just holder. " + result);
            }
        });
        mGenerateDataAndKeyWithECC = (Button) findViewById(R.id.btn_gendatakeywithecc);
        mGenerateDataAndKeyWithECC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // need update data in c
                long result = SdEncrypt.GenDataAndKeyWithECC(deviceHandle);
                tvResult.setText("GenDataAndKeyWithECC: " + result);
            }
        });
        mExportPublicKey = (Button) findViewById(R.id.btn_exportpublickey);
        mExportPublicKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                byte[] result = SdEncrypt.ExportPublicKey(deviceHandle);
                if (result != null) {
                    PublicKey = EncryptUtil.ByteArrayToHexString(result);
                }
                tvResult.setText("ExportPublicKey: " + PublicKey);
            }
        });
        mImportSessionKey = (Button) findViewById(R.id.btn_exportsessionkey);
        mImportSessionKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                String symKey = "11c88ae04cec1ba554d03d5b5970333a83585826c2a985de5520d9e934389efb84b52d344fb21aa8ea38a4940c8332692b8d4da2393549212eafdc0f11ca5c9c2a9abb548ddab4a9aec43f1ffad694020771b007d1d0b3bf17915766f28e52e5500d103ac4422698d989a7affd0a62df";
                KeyData = "11c88ae04cec1ba554d03d5b5970333a83585826c2a985de5520d9e934389efb84b52d344fb21aa8ea38a4940c8332692b8d4da2393549212eafdc0f11ca5c9c4a0d639572735fdda4041ff8a70423be9e1b4a6c99bfcac73492b9a5a23beb7f2dab084ebf802dd61f262e400ae8971b";
                byte[] key = EncryptUtil.HexStringToByteArray(KeyData);
                Log.i(TAG, "====== mImportSesKey = " + KeyData);
                long result = SdEncrypt.ImportSessionKey(deviceHandle);
                tvResult.setText("ImportSessionKey: " + result);
            }
        });
        mCloseHandle = (Button) findViewById(R.id.btn_closehandle);
        mCloseHandle.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.CloseHandle(deviceHandle);
                tvResult.setText("CloseHandle: " + result);
            }
        });
        mGetDevInfo = (Button) findViewById(R.id.btn_getdevinfo);
        mGetDevInfo.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = SdEncrypt.GetDevInfo(deviceHandle);
                tvResult.setText("GetDevInfo: " + result);
            }
        });
        mGetZA = (Button) findViewById(R.id.btn_getza);
        mGetZA.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(KeyHandle)) {
                    KeyHandle = "078a94425d8f991402af39cfa894dd26f76a05fd9fffc078f558119371b50585078a94425d8f991402af39cfa894dd26f76a05fd9fffc078f558119371b50585";
                }
//                boolean result = SkfInterface.getSkfInstance().SKF_GetZA(deviceName, EncryptUtil.HexStringToByteArray(KeyHandle));
                long result = SdEncrypt.GetZA(deviceHandle, EncryptUtil.HexStringToByteArray(KeyHandle));
                tvResult.setText("GetZA: " + result);
            }
        });
        mNextPage = (Button) findViewById(R.id.btn_nextpage);
        mNextPage.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, SyncActivity.class);
                intent.putExtra(EncryptUtil.DEVICE_NAME, deviceName);
                intent.putExtra(EncryptUtil.SYMKEY_HANDLE, KeyData);
                intent.putExtra(EncryptUtil.KEY_HANDLE, KeyHandle);
                startActivity(intent);
            }
        });

        // need init
        callTongfang();
    }

    private void callTongfang() {
        appsDir = getExternalFilesDir(null);
        Log.i(TAG, "=============appsDir: " + appsDir.toString());
//        String appPath = "Android/data/" + getPackageName();
        String appPath = getPackageName();
        long result = SdEncrypt.setPackageName(appPath);
        Log.i(TAG, "appPath: " + appPath);
        Log.i(TAG, "setPackageName result: " + result);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            if (ContextCompat.checkSelfPermission(MainActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE)!= PackageManager.PERMISSION_GRANTED){
                ActivityCompat.requestPermissions(MainActivity.this,new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},1);
            }
        }
        ArrayList<StorageBean> gg = StorageUtils.getStorageData(getApplicationContext());
        StringBuilder cardBuilder = new StringBuilder(256);
        for (StorageBean bean: gg) {
            Log.d("MainActivity", "bean.getPath(): " + bean.getPath());
            Log.d("MainActivity", "bean.getTotalSize(): " + bean.getTotalSize());
            cardBuilder.append(bean.getPath() + "\n");
            if (!bean.getPath().toLowerCase().contains("emulated")) {
//                extPath = bean.getPath();
                StorageUtils.EXTERNAL_SDCARD = bean.getPath();
                break;
            }
        }
        Log.i(TAG, "cardBuilder: " + cardBuilder.toString());
        extPath = StorageUtils.EXTERNAL_SDCARD + "/Android/data/" + getPackageName();
        Log.i(TAG, "extPath: " + extPath);
        tvLog.setText("ExternalFilesDir: " + extPath);
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions, @NonNull int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        switch (requestCode){
            case 1:
                if (grantResults.length>0&&grantResults[0]!=PackageManager.PERMISSION_GRANTED){
                    finish();
                }
                break;
        }
    }

}
