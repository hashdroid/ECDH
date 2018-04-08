package com.example.project1.ecc_1;

import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.SharedPreferences;
import android.os.AsyncTask;
import android.os.Environment;
import android.preference.PreferenceManager;
import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.view.Window;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.KeyPair;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends Activity  {
    private static String TAG = MainActivity.class.getSimpleName();

    private static String KPA_KEY = "kpA";
    private static String KPB_KEY = "kpB";

    private static final String CURVE_NAME = "secp160k1";

    private Button b2;
    private Button b3;
    private TextView t1;
    private TextView t2;
    private TextView t3;
    private TextView t4;
    private TextView t5;
    private TextView t6;
    private Crypto crypto;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
         final SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        setProgressBarIndeterminateVisibility(false);
        crypto=Crypto.getInstance();

        b2=(Button)findViewById(R.id.b2);
        b3=(Button)findViewById(R.id.b3);

        b2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                ecdh(prefs);
            }
        });
        b3.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clear(prefs);
            }
        });

        t1=(TextView)findViewById(R.id.t1);
        t2=(TextView)findViewById(R.id.t2);
        t3=(TextView)findViewById(R.id.t3);
        t4=(TextView)findViewById(R.id.t4);
        t5=findViewById(R.id.t5);
        t6=findViewById(R.id.t6);

    }

    protected void onStart()
    {
        final SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        super.onStart();
        generateKeys(prefs);
    }




    @SuppressLint("StaticFieldLeak")
    private void generateKeys(SharedPreferences prefs) {
         final SharedPreferences.Editor prefsEditor = prefs.edit();

        new AsyncTask<Void, Void, Boolean>() {

            ECParams ecp;
            Exception error;

            @Override
            protected void onPreExecute() {
                Toast.makeText(MainActivity.this, "Generating ECDH keys...",
                        Toast.LENGTH_SHORT).show();

                //setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected Boolean doInBackground(Void... arg0) {
                try {
                    ecp = ECParams.getParams(CURVE_NAME);
                    KeyPair kpA = crypto.generateKeyPairParams(ecp);

                    KeyPair kpB = crypto.generateKeyPairNamedCurve(CURVE_NAME);

                    saveKeyPair(prefsEditor, KPA_KEY, kpA);
                    saveKeyPair(prefsEditor, KPB_KEY, kpB);

                    return prefsEditor.commit();
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return false;
                }
            }

            @Override
            protected void onPostExecute(Boolean result) {
                setProgressBarIndeterminateVisibility(false);

                if (result) {


                    Toast.makeText(MainActivity.this,
                            "Successfully generated and saved keys.",
                            Toast.LENGTH_SHORT).show();
                } else {
                    Toast.makeText(
                            MainActivity.this,
                            error == null ? "Error saving keys" : error
                                    .getMessage(), Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }

    @SuppressLint("StaticFieldLeak")
    private void ecdh(final SharedPreferences prefs) {
        new AsyncTask<Void, Void, String[]>() {

            Exception error;

            @Override
            protected void onPreExecute() {

                Toast.makeText(MainActivity.this,
                        "Calculating shared ECDH key...", Toast.LENGTH_SHORT)
                        .show();

                setProgressBarIndeterminateVisibility(true);
            }

            @Override
            protected String[] doInBackground(Void... arg0) {
                try {
                    KeyPair kpA = readKeyPair(prefs, KPA_KEY);
                    if (kpA == null) {
                        throw new IllegalArgumentException(
                                "Key A not found. Generate keys first.");
                    }
                    KeyPair kpB = readKeyPair(prefs, KPB_KEY);
                    if (kpB == null) {
                        throw new IllegalArgumentException(
                                "Key B not found. Generate keys first.");
                    }

                    byte[] aSecret = crypto.ecdh(kpA.getPrivate(),
                            kpB.getPublic());
                    byte[] bSecret = crypto.ecdh(kpB.getPrivate(),
                            kpA.getPublic());



                    return new String[] { Crypto.hex(aSecret),
                            Crypto.hex(bSecret) };
                } catch (Exception e) {
                    Log.e(TAG, "Error doing ECDH: " + e.getMessage(), error);
                    error = e;

                    return null;
                }
            }



            @Override
            protected void onPostExecute(String[] result){
                setProgressBarIndeterminateVisibility(false);
                try {
                    //String input=keygath();
                    String i=blowfish();

                    t6.setText(i);
                    String dec=blowfishdec(i);
                    t5.setText(dec);

                } catch (Exception e) {
                    e.printStackTrace();
                }
                if (result != null && error == null) {
                    t2.setText(result[0]);
                    t4.setText(result[1]);

                } else {
                    Toast.makeText(MainActivity.this, error.getMessage(),
                            Toast.LENGTH_LONG).show();
                }
            }

        }.execute();
    }
    public String keygath() throws Exception {
        final SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        //SharedPreferences.Editor prefsEditor = prefs.edit();

        KeyPair kpA = readKeyPair(prefs, KPA_KEY);
        String input=kpA.getPrivate().toString();
        //prefsEditor.putString(KPA_KEY+ "_private", String.valueOf(output));
        //String privKey = prefs.getString(KPA_KEY + "_private", null);
        return input;

    }

    private void clear(SharedPreferences prefs) {
        //curveNameText.setText("");
        //fpSizeText.setText("");
        t2.setText("");
        t4.setText("");

        SharedPreferences.Editor prefsEditor = prefs.edit();
        prefsEditor.putString(KPA_KEY + "_private", null);
        prefsEditor.putString(KPA_KEY + "_public", null);
        prefsEditor.putString(KPB_KEY + "_private", null);
        prefsEditor.putString(KPB_KEY + "_public", null);

        prefsEditor.commit();

        Toast.makeText(MainActivity.this, "Deleted keys.", Toast.LENGTH_LONG)
                .show();
    }

    private void saveKeyPair(SharedPreferences.Editor prefsEditor, String key,
                             KeyPair kp) throws Exception {
        String pubStr = Crypto.base64Encode(kp.getPublic().getEncoded());
        String privStr = Crypto.base64Encode(kp.getPrivate().getEncoded());


        prefsEditor.putString(key + "_public", pubStr);
        prefsEditor.putString(key + "_private", privStr);



    }

    @SuppressWarnings("unused")
    private void saveToFile(String filename, byte[] bytes) throws Exception {
        File file = new File(Environment.getExternalStorageDirectory(),
                filename);
        if(!file.exists())
        {file.createNewFile();}
        FileOutputStream fos = new FileOutputStream(file);
        fos.write(bytes);
        fos.flush();
        fos.close();
    }

    private KeyPair readKeyPair(SharedPreferences prefs, String key)
            throws Exception {
        String pubKeyStr = prefs.getString(key + "_public", null);
        String privKeyStr = prefs.getString(key + "_private", null);



        if (pubKeyStr == null || privKeyStr == null) {
            return null;
        }

        return crypto.readKeyPair(pubKeyStr, privKeyStr);
    }

    public String blowfish() throws Exception{
         final SharedPreferences prefs1 = PreferenceManager
                .getDefaultSharedPreferences(this);
        final SharedPreferences prefs = PreferenceManager
                .getDefaultSharedPreferences(this);
        SharedPreferences.Editor prefsEditor = prefs1.edit();
         final String ALGORITHM = "Blowfish";
         String test = "helloworld";
         String keyString = "2356a3a42ba5781f80";
         Key secretKey = new SecretKeySpec(keyString.getBytes(), ALGORITHM);
         Cipher cipher = Cipher.getInstance(ALGORITHM);
         cipher.init(Cipher.ENCRYPT_MODE,secretKey);
         KeyPair kpA = readKeyPair(prefs, KPA_KEY);
         String input=kpA.getPrivate().toString();
         byte[] output1=cipher.doFinal(test.getBytes());
         //String enc=bytesToHex(output1);
         prefsEditor.putString(KPA_KEY+ "_private", output1.toString());
        String privKey = prefs1.getString(KPA_KEY + "_private", null);

        return output1.toString();


    }

    public static String bytesToHex(byte[] data) {

        if (data == null)
            return null;

        String str = "";

        for (int i = 0; i < data.length; i++) {
            if ((data[i] & 0xFF) < 16)
                str = str + "0" + java.lang.Integer.toHexString(data[i] & 0xFF);
            else
                str = str + java.lang.Integer.toHexString(data[i] & 0xFF);
        }

        return str;

    }

    public String blowfishdec(String input) throws Exception{
try{
        final String ALGORITHM = "Blowfish";
        String keyString = "2356a3a42ba5781f80";
        Key secretKey = new SecretKeySpec(keyString.getBytes(), ALGORITHM);
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE,secretKey);
        byte[] inp=input.getBytes();
        byte[] output=cipher.doFinal(inp);
        Log.e("******",output.toString());

        }
        catch(Exception e)
        {
            Log.e("err",e.getMessage());
        }

        return "";
    }



}
