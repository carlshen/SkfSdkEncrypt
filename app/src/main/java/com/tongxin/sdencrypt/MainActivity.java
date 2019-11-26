package com.tongxin.sdencrypt;

import android.Manifest;
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
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import com.tongxin.sdjni.SdEncrypt;

import java.util.ArrayList;

/**
 * Created by carl on 19-11-12.
 *
 * 用于公司的项目验证。
 */
public class MainActivity extends AppCompatActivity implements View.OnClickListener {
    public final String TAG = "tongxin";
    private TextView text;
    private TextView tvResult;
    private boolean flag = true;
    private String testFile = "TEST.txt";
    private static int KEY_LENGTH = 2024;
    private TextView textVersion;
    private String extPath;
    private String extFile = null;
    private EditText etKey = null;
    private EditText etData = null;
    private EditText etReadOff = null;
    private EditText etReadLen = null;
    private EditText etInputOff = null;
    private EditText etgetLen = null;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        View v = findViewById(R.id.get_version);
        if (v != null)
            v.setOnClickListener(this);
        v = findViewById(R.id.input_key);
        if (v != null)
            v.setOnClickListener(this);
        v = findViewById(R.id.read_key);
        if (v != null)
            v.setOnClickListener(this);
        v = findViewById(R.id.write_data);
        if (v != null)
            v.setOnClickListener(this);

        textVersion = (TextView) findViewById(R.id.tv_version);
        text = (TextView) findViewById(R.id.status);
        tvResult = (TextView) findViewById(R.id.result);
        etKey = (EditText) findViewById(R.id.et_key);
        etData = (EditText) findViewById(R.id.et_data);
        etReadOff = (EditText) findViewById(R.id.et_read_off);
        etReadLen = (EditText) findViewById(R.id.et_read_len);
        etInputOff = (EditText) findViewById(R.id.et_key_off);
        etgetLen = (EditText) findViewById(R.id.et_get_len);
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
                extPath = bean.getPath();
                StorageUtils.EXTERNAL_SDCARD = bean.getPath();
                break;
            }
        }
        extPath = StorageUtils.EXTERNAL_SDCARD;
        text.setText("ExternalFilesDir: " + StorageUtils.EXTERNAL_SDCARD);
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

    @Override
    public void onClick(View view) {
        int id = view.getId();
        switch (id) {
            case R.id.get_version:
                try {
                    String result = SdEncrypt.getSdInstance().getver();
                    textVersion.setText("GetVersion: " + result);
                } catch (Exception arg1) {
                    arg1.printStackTrace();
                }
                break;
            case R.id.read_key:
                int off = 0;
                int len = 0;
                try {
                    off = Integer.parseInt(etReadOff.getText().toString().trim());
                    len = Integer.parseInt(etReadLen.getText().toString().trim());
                    if (off < 0) {
                        off = 0;
                    }
                    if (len < 1) {
                        text.setText("Input key should be longer than 0.");
                        return;
                    }
                } catch (Exception arg2) {
                    arg2.printStackTrace();
                }
                try {
//                    byte[] result = SdEncrypt.getSdInstance().readkey2(StorageUtils.EXTERNAL_SDCARD + StorageUtils.EXTERNAL_PATH + "/Key.bin", off, len);
                    byte[] result = SdEncrypt.getSdInstance().readkey(off, len);
                    String src = toHexString(result);
                    Log.d("MainActivity", "GetKey: " + src);
                    text.setText("GetKey: " + src);
                } catch (Exception arg5) {
                    arg5.printStackTrace();
                }
                break;
            case R.id.input_key:
                String inKey = etKey.getText().toString().trim();
                if (TextUtils.isEmpty(inKey)) {
                    Toast.makeText(getApplicationContext(), "please input key", Toast.LENGTH_SHORT);
                    text.setText("please input key.");
                    return;
                }
                int inputOff = 0;
                try {
                    inputOff = Integer.parseInt(etInputOff.getText().toString().trim());
                    if (inputOff < 0) {
                        inputOff = 0;
                    }
                } catch (Exception arg3) {
                    arg3.printStackTrace();
                }
                try {
                    byte[] src = toByteArray(inKey);
                    Log.d("MainActivity", "inputOff: " + inputOff);
                    Log.d("MainActivity", "src.length(): " + src.length);
                    Log.d("MainActivity", "src: " + toHexString(src));
                    int result = SdEncrypt.getSdInstance().inputkey(src, inputOff, src.length);
//                    int result = SdEncrypt.getSdInstance().inputkey2(StorageUtils.EXTERNAL_SDCARD + StorageUtils.EXTERNAL_PATH + "/Key.bin", src, inputOff, src.length);
                    text.setText("inputkey result: " + result);
                } catch (Exception arg3) {
                    arg3.printStackTrace();
                }
                break;
            case R.id.write_data:
                String inData= etData.getText().toString().trim();
                if (TextUtils.isEmpty(inData)) {
                    Toast.makeText(getApplicationContext(), "please input data", Toast.LENGTH_SHORT);
                    text.setText("please input data to transmit.");
                    return;
                }
                int getLen = 0;
                try {
                    getLen = Integer.parseInt(etgetLen.getText().toString().trim());
                    if (getLen < 0) {
                        getLen = 0;
                    }
                } catch (Exception arg8) {
                    arg8.printStackTrace();
                }
                try {
                    byte[] src = toByteArray(inData);
                    Log.d("MainActivity", "src.length(): " + src.length);
                    Log.d("MainActivity", "src: " + toHexString(src));
                    byte[] result = SdEncrypt.getSdInstance().transmitdata(src, src.length, getLen);
//                    byte[] result = SdEncrypt.getSdInstance().transmitdata2(StorageUtils.EXTERNAL_SDCARD + StorageUtils.EXTERNAL_PATH + "/Security.bin", src, src.length, getLen);
                    String dst = toHexString(result);
                    text.setText("receive result: " + dst);
                    Log.d("MainActivity", "  === result: " + dst);

                    // next is the transmit data1 method
//                    String trData1 = SdEncrypt.getSdInstance().transmitdata1(StorageUtils.EXTERNAL_SDCARD + StorageUtils.EXTERNAL_PATH + "/Security.bin", inData, inData.length(), getLen);
//                    Log.d("MainActivity", "  === result: " + trData1);
//                    text.setText("receive result: " + trData1);
                } catch (Exception arg9) {
                    arg9.printStackTrace();
                }
                break;
        }
    }

    void writeFileTest() {
        Log.d("MainActivity", "writeFileTest() getSuggestStoragePath = " + StorageUtils.getSuggestStoragePath(getApplicationContext()));
        if (flag) {
            flag = false;
            boolean result = StorageUtils.writeString(extPath, testFile, "" + System.currentTimeMillis());
            Log.d("MainActivity", "writeString result = "  + result);
            text.setText("Write file result: " + result);
            flag = true;
        }
    }

    void writeNewFileTest() {
        Log.d("MainActivity", "writeNewFileTest() getSuggestStoragePath = " + StorageUtils.getSuggestStoragePath(getApplicationContext()));
        if (flag) {
            flag = false;
            extFile = System.currentTimeMillis() + ".txt";
            boolean result = StorageUtils.writeString(extPath, extFile, "" + System.currentTimeMillis());
            Log.d("MainActivity", "writeNewFileTest result = "  + result);
            text.setText("Write new file result: " + result);
            flag = true;
        }
    }

    public String toHexString(byte[] byteArray) {
        String str = null;
        if (byteArray != null && byteArray.length > 0) {
            StringBuffer stringBuffer = new StringBuffer(byteArray.length);
            for (byte byteChar : byteArray) {
                stringBuffer.append(String.format("%02X", byteChar));
            }
            str = stringBuffer.toString();
        }
        return str;
    }
    public byte[] toByteArray(String hexString) {
        hexString = hexString.toLowerCase();
        final byte[] byteArray = new byte[hexString.length() / 2];
        int k = 0;
        for (int i = 0; i < byteArray.length; i++) {// 因为是16进制，最多只会占用4位，转换成字节需要两个16进制的字符，高位在先
            byte high = (byte) (Character.digit(hexString.charAt(k), 16) & 0xff);
            byte low = (byte) (Character.digit(hexString.charAt(k + 1), 16) & 0xff);
            byteArray[i] = (byte) (high << 4 | low);
            k += 2;
        }
        return byteArray;
    }

}
