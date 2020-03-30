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

/**
 * Created by carl on 20-02-06.
 *
 * 用于公司的项目验证。
 */
public class SyncActivity extends AppCompatActivity {

    public static final String TAG = "SyncActivity";
    private TextView tvResult = null;
    private TextView tvLog = null;
    // next 2nd page
    private Button mSetSymKey = null;
    private Button mGetSymKey = null;
    private Button mCheckSymKey = null;
    // encrypt / decrypt
    private Button mEncryptInit = null;
    private Button mEncrypt = null;
    private Button mEncryptUpdate = null;
    private Button mEncryptFinal = null;
    private Button mDecryptInit = null;
    private Button mDecrypt = null;
    private Button mDecryptUpdate = null;
    private Button mDecryptFinal = null;
    private Button mDigestInit = null;
    private Button mDigest = null;
    private Button mDigestUpdate = null;
    private Button mDigestFinal = null;
    private Button mMacInit = null;
    private Button mMacUpdate = null;
    private Button mMacFinal = null;
    private Button mGenerateKey = null;
    private Button mECCExportSessionKey = null;
    private Button mECCPrvKeyDecrypt = null;
    private Button mImportKeyPair = null;
    private Button mCipher = null;

    private String mECCData = null;
    private String ECCKeyPair = null;
    private int deviceHandle = -1;
    private String deviceName = null;
    private String deviceData = null;
    private String KeyData = null;
    private String EncrpytData = null;
    private String DecrpytData = null;
    private String EncrpytUpdateData = null;
    private String DecrpytUpdateData = null;
    private String EncrpytFinalData = null;
    private String DecrpytFinalData = null;
    private String KeyHandle = null;
    private String PublicKey = null;
    private String PrivateKey = null;
    private String DigestData = null;
    private String DigestUpdateData = null;
    private String DigestFinalData = null;
    private String MacData = null;
    private String MacUpdateData = null;
    private String MacFinalData = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sync);
        Intent intent = getIntent();
        if (intent != null) {
            deviceName = intent.getStringExtra(EncryptUtil.DEVICE_NAME);
            KeyData = intent.getStringExtra(EncryptUtil.SYMKEY_HANDLE);
            KeyHandle = intent.getStringExtra(EncryptUtil.KEY_HANDLE);
        }
        Log.i(TAG, "onCreate =========== deviceName = " + deviceName);
        Log.i(TAG, "onCreate ============== KeyData = " + KeyData);
        Log.i(TAG, "onCreate ============ KeyHandle = " + KeyHandle);

        tvResult = (TextView) findViewById(R.id.tv_result);
        tvLog = (TextView) findViewById(R.id.tv_log);

        mSetSymKey = (Button) findViewById(R.id.btn_setsymkey);
        mSetSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String symKey = "";
                byte[] key = null;
                try {
                    key = EncryptUtil.generateKey();
                    symKey = EncryptUtil.ByteArrayToHexString(key);
                } catch (Exception e) {
                    e.printStackTrace();
                }
                Log.i(TAG, "====== mSetSymKey = " + symKey);
                long result = SdEncrypt.SetSymKey(deviceHandle, key);
                tvResult.setText("SetSymKey: " + result);
            }
        });
        mGetSymKey = (Button) findViewById(R.id.btn_getsymkey);
        mGetSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String result = SdEncrypt.GetSymKey(deviceHandle);
                tvResult.setText("CloseHandle: " + result);
            }
        });
        mCheckSymKey = (Button) findViewById(R.id.btn_checksymkey);
        mCheckSymKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.CheckSymKey(deviceHandle);
                tvResult.setText("GetDevInfo: " + result);
            }
        });
        mEncryptInit = (Button) findViewById(R.id.btn_encryptInit);
        mEncryptInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.EncryptInit(deviceHandle);
                tvResult.setText("EncryptInit: " + result);
            }
        });
        mEncrypt = (Button) findViewById(R.id.btn_encrypt);
        mEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("112233445566778899001122334455667788aabb");
                }
                EncrpytData = encbuilder.toString();
                byte[] result = SdEncrypt.Encrypt(deviceHandle, EncrpytData.getBytes());
                tvResult.setText("Encrypt: " + EncryptUtil.ByteArrayToHexString(result));
            }
        });
        mEncryptUpdate = (Button) findViewById(R.id.btn_encryptupdate);
        mEncryptUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                // maybe need several times
                for (int loop = 0; loop < 3; loop++) {
                    StringBuilder encbuilder = new StringBuilder(256);
                    for (int i = 0; i < 8; i++) {
                        encbuilder.append("11223344556677889900112233445566");
                    }
                    EncrpytUpdateData = encbuilder.toString();
                    DecrpytUpdateData = encbuilder.toString();
//                    boolean result = SkfInterface.getSkfInstance().SKF_EncryptUpdate(KeyData, EncryptUtil.HexStringToByteArray(DecrpytUpdateData));
//                    tvResult.setText("SKF_EncryptUpdate loop " + loop + " : " + result);
                }
                long result = SdEncrypt.EncryptUpdate(deviceHandle);
                tvResult.setText("EncryptUpdate: " + result);
            }
        });
        mEncryptFinal = (Button) findViewById(R.id.btn_encryptfinal);
        mEncryptFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(128);
                for (int i = 0; i < 2; i++) {
                    encbuilder.append("11223344556677889900112233445566");
                }
                EncrpytFinalData = encbuilder.toString();
                DecrpytFinalData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_EncryptFinal(KeyData, EncryptUtil.HexStringToByteArray(EncrpytFinalData));
                long result = SdEncrypt.EncryptFinal(deviceHandle);
                tvResult.setText("EncryptFinal: " + result);
            }
        });
        mDecryptInit = (Button) findViewById(R.id.btn_decryptInit);
        mDecryptInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.DecryptInit(deviceHandle);
                tvResult.setText("DecryptInit: " + result);
            }
        });
        mDecrypt = (Button) findViewById(R.id.btn_decrypt);
        mDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytData)) {
                    tvResult.setText("SKF_Decrypt: There is no decrypt data");
                    return;
                }
                // DecrpytData is get from encrypt result
//                boolean result = SkfInterface.getSkfInstance().SKF_Decrypt(KeyData, EncryptUtil.HexStringToByteArray(DecrpytData));
                long result = SdEncrypt.Decrypt(deviceHandle);
                tvResult.setText("Decrypt: " + result);
            }
        });
        mDecryptUpdate = (Button) findViewById(R.id.btn_decryptupdate);
        mDecryptUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytUpdateData)) {
                    tvResult.setText("SKF_DecryptUpdate: There is no decrypt data");
                    return;
                }
                long result = SdEncrypt.DecryptUpdate(deviceHandle);
                tvResult.setText("DecryptUpdate: " + result);
            }
        });
        mDecryptFinal = (Button) findViewById(R.id.btn_decryptfinal);
        mDecryptFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (TextUtils.isEmpty(DecrpytFinalData)) {
                    tvResult.setText("SKF_DecryptFinal: There is no decrypt data");
                    return;
                } else {
                    tvLog.setText("SKF_DecryptFinal: tested with SKF_DecryptUpdate");
                }
                long result = SdEncrypt.DecryptFinal(deviceHandle);
                tvResult.setText("DecryptFinal: " + result);
            }
        });
        mDigestInit = (Button) findViewById(R.id.btn_digestInit);
        mDigestInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.DigestInit(deviceHandle);
                tvResult.setText("DigestInit: " + result);
            }
        });
        mDigest = (Button) findViewById(R.id.btn_digest);
        mDigest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(1024);
                for (int i = 0; i < 28; i++) {
                    encbuilder.append("1122334455667788990011223344556677889900");
                }
                DigestData = encbuilder.toString();
                long result = SdEncrypt.Digest(deviceHandle);
                tvResult.setText("Digest: " + result);
                tvLog.setText("DigestData: " + DigestData);
            }
        });
        mDigestUpdate = (Button) findViewById(R.id.btn_digestupdate);
        mDigestUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(256);
                for (int i = 0; i < 8; i++) {
                    encbuilder.append("11223344556677889900112233445566");
                }
                DigestUpdateData = encbuilder.toString();
                long result = SdEncrypt.DigestUpdate(deviceHandle);
                tvResult.setText("DigestUpdate: " + result);
                tvLog.setText("DigestUpdateData: " + DigestUpdateData);
            }
        });
        mDigestFinal = (Button) findViewById(R.id.btn_digestfinal);
        mDigestFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                DigestFinalData = "1122334455667788990011223344556677889900";
                long result = SdEncrypt.DigestFinal(deviceHandle);
                tvResult.setText("DigestFinal: " + result);
                tvLog.setText("DigestFinalData: " + DigestFinalData);
            }
        });
        mMacInit = (Button) findViewById(R.id.btn_MacInit);
        mMacInit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.MacInit(deviceHandle);
                tvResult.setText("MacInit: " + result);
            }
        });
        mMacUpdate = (Button) findViewById(R.id.btn_MacUpdate);
        mMacUpdate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                StringBuilder encbuilder = new StringBuilder(256);
                for (int i = 0; i < 8; i++) {
                    encbuilder.append("11223344556677889900112233445566");
                }
                MacUpdateData = encbuilder.toString();
//                boolean result = SkfInterface.getSkfInstance().SKF_MacUpdate(EncryptUtil.HexStringToByteArray(MacUpdateData));
                long result = SdEncrypt.MacUpdate(deviceHandle);
                tvResult.setText("MacUpdate: " + result);
                tvLog.setText("MacUpdateData: " + MacUpdateData);
            }
        });
        mMacFinal = (Button) findViewById(R.id.btn_MacFinal);
        mMacFinal.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                MacFinalData = "1122334455667788990011223344556677889900";
//                boolean result = SkfInterface.getSkfInstance().SKF_MacFinal(EncryptUtil.HexStringToByteArray(MacFinalData));
                long result = SdEncrypt.MacFinal(deviceHandle);
                tvResult.setText("MacFinal: " + result);
                tvLog.setText("MacFinalData: " + MacFinalData);
            }
        });
        mGenerateKey = (Button) findViewById(R.id.btn_generatekey);
        mGenerateKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.GenerateKey(deviceHandle);
                tvResult.setText("GenerateKey: " + result);
            }
        });
        mECCExportSessionKey = (Button) findViewById(R.id.btn_eccexportkey);
        mECCExportSessionKey.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                PublicKey = "b2c5f9be02b7dab8d8312b0ac8fb30bbedc79bee51d19efd647d2dbbd6f5e9078ad7837eeddcec2718a691d3c6c0a5dad6c53976b23f39c131a3f37a6d20eb33";
//                KeyHandle = "165f7e824236b90d88aab9ebffe8548a3b88a98cac5c7033fe69c7cfbb061ed6";
                if (TextUtils.isEmpty(KeyData)) {
                    KeyData = KeyHandle;
                }
                KeyData = "13BCEC3A7BC6AEC89E6E26E95A01B1EDEEB36C0622DBBA84782FD5D83F9A1BC6";
//                boolean result = SkfInterface.getSkfInstance().SKF_ECCExportSessionKeyByHandle(deviceName, EncryptUtil.HexStringToByteArray(PublicKey), EncryptUtil.HexStringToByteArray(KeyData), "C002");
                long result = SdEncrypt.ECCExportSessionKey(deviceHandle);
                tvResult.setText("ECCExportSessionKey: " + result);
            }
        });
        mECCPrvKeyDecrypt = (Button) findViewById(R.id.btn_ecckeydecrypt);
        mECCPrvKeyDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
//                DigestData = "11c88ae04cec1ba554d03d5b5970333a83585826c2a985de5520d9e934389efb84b52d344fb21aa8ea38a4940c8332692b8d4da2393549212eafdc0f11ca5c9c550443b810f3308b839fed0becd6ec53151d64f661130e9b6156190f2db9139d2fed5b6413e5062fb3d8c7b7e366b8268e60aad010a7fcfca34808c23a123fba4c2663ebb6b7260c2a546c0ee1b849a8ddf62f0d3e56c936994b956804ca87bdec93cfc6e966c3c950568eecf1662f29510ee970cf51195b793da8ee41359c356c217e5d16c2d44146e807976b05d4bd1ea68765560b89de45342a55f9e2d0990ad018807b160b7415ba91361f9b1fae3ffc805638beb6a9207db8cd042f893903c944b679c14cb45fc4e013ffc85e8fb4b260f362dc8cce2a51198f06063424c15acfa17f2df17ea5cf043bbba470f4f0ebc9602139b5acc135f5b5db51dbceb331b05190873d1bedaeb918809d3765cfddfc4f8c4c6b270f896eb15939c522f1c9ec07f21ec10495e5a9bf40989ddaea0af359bce9449cf5b3fa91743963d809514e81e459511e4e76fd6b76e9d6d325ef93cc3a6b61e0bc306a43df3f487ad67f54c8ae1c4e7d966ad9dba1146e7dc398b751b9a8964f6ccb2843dcb0660a06e237a911ec11e269dfc72a36efc6dfef19d98ac01b5316a7d8443cc62babed504e13a0cf3c5caaf19460376dea5a55860df9e4378527142ea140f0f230ecf1";
                DigestData = "11c88ae04cec1ba554d03d5b5970333a83585826c2a985de5520d9e934389efb84b52d344fb21aa8ea38a4940c8332692b8d4da2393549212eafdc0f11ca5c9c8881f6869db4221487280694553177f05a208d2aae0ce5a4a894772d6542da2d1d9f73f2adc987fd40a43b5cbc360d979557821f658d79aa8969972f89b981b60a16eccf49aaf0edba4a0cc7ddf6b603c5c527f8dc90a5a768f3f57af44a093b7b4cd5bc87f2e02973ca973fb51dede0f49dae44fe157945b5bd8499416df8ca35607614a62614d04886532dc5b256a8b280425e66dd7a35caf489689720ecdd35a5a146530eec2e33f3677cc7859c2420d42645bf2cf311fee3bb12dfd00c7a0cb95fc26668b645d8072105756b08731d344b99121fef66a4e0fcf395cf3cb04b338de045de79715011c568f658225f0aa66171d52e026bccf07eb5c49b47764d41020109f0f87fec58c446785c918c2058bccce849306064f3b5b7bd0baae9340faee20b591042ddb197139dc1b8fbd93d102aa1205787d7632ec16683eebda8741ed74570c03d7667a87c6ad7fc0010288f7bfd2c8809c4a8192f8bd56e3ad26ce2c599272e206b864a0e914aba17307c5d10718ef0388cbe865ff49cf0ac6f2274be7c8a75d6c973eecb2738fe652db4fdd2981f41e148d33f4d8cb9e86d0330dd5ad8eefd927695169b0a832042e0652c0553db57ebe8d6c48af1f0b2c9";
                Log.i(TAG, "====== SKF_ECCPrvKeyDecrypt Data = " + DigestData);
//                boolean result = SkfInterface.getSkfInstance().SKF_ECCPrvKeyDecrypt(deviceName, EncryptUtil.HexStringToByteArray(DigestData), "A101");
                long result = SdEncrypt.ECCPrvKeyDecrypt(deviceHandle);
                tvResult.setText("ECCPrvKeyDecrypt: " + result);
            }
        });
        mImportKeyPair = (Button) findViewById(R.id.btn_importkey);
        mImportKeyPair.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                PublicKey = "2A687F6E9B405E6A8AE0E054E0EA1F52B9D21BB9731F9B9DE403B2A20F39EDA2F434B3BAE032014ACAA9DA293DBA2D7CA6D0BEFF2AC3FDC52040FBFCC28C2B68";
                PrivateKey = "28BDA35F176245ADA0F02F24F41D45F9A59FACA737124EBB79148D8AE83705B2";
//                boolean result = SkfInterface.getSkfInstance().SKF_ImportKeyPair(deviceName, EncryptUtil.HexStringToByteArray(PublicKey), EncryptUtil.HexStringToByteArray(PrivateKey), "A101");
                long result = SdEncrypt.ImportKeyPair(deviceHandle);
                tvResult.setText("ImportKeyPair: " + result);
            }
        });
        mCipher = (Button) findViewById(R.id.btn_cipher);
        mCipher.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                long result = SdEncrypt.Cipher(deviceHandle);
                tvResult.setText("Cipher: " + result);
            }
        });
    }

    @Override
    protected void onResume() {
        super.onResume();
        if (Build.VERSION.SDK_INT>=Build.VERSION_CODES.M){
            if (ContextCompat.checkSelfPermission(SyncActivity.this, Manifest.permission.WRITE_EXTERNAL_STORAGE)!= PackageManager.PERMISSION_GRANTED){
                ActivityCompat.requestPermissions(SyncActivity.this,new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},1);
            }
        }
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
