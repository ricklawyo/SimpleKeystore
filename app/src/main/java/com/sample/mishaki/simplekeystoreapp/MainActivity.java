package com.sample.mishaki.simplekeystoreapp;

import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.preference.PreferenceManager;
import android.security.KeyPairGeneratorSpec;
import android.os.Bundle;
import android.support.v7.app.AlertDialog;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Enumeration;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.security.auth.x500.X500Principal;


public class MainActivity extends AppCompatActivity {

    static final String TAG = "SimpleKeystoreApp";
    static final String CIPHER_TYPE = "RSA/ECB/PKCS1Padding";

    EditText userIDText;
    EditText pwText, decryptedText, encryptedText;
    List<String> userIDsInKeystore;
    ListView listView;
    KeyRecyclerAdapter listAdapter;
    CheckBox cbCorrectPW;
    KeyStore keyStore;
    SharedPreferences sharedPref;

    // sets up the inital state of the main activity
    // including setting up the listview and listview adapter
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        try {
            // connect to the KeyStore on the device
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);

            // now open the default shared preferences for this app
            sharedPref = PreferenceManager.getDefaultSharedPreferences(this);



        }
        catch(Exception e) {}

        // gets a list of all of the keys for this app
        //  in your case, the list of keys/aliases would be
        //  all the users where each user is an alias.  This
        //  method just adds all the aliases to an ArrayList
        refreshKeys();

        // Standard UI view setup stuff I assume you know what it does....
        setContentView(R.layout.activity_main);

        View listHeader = View.inflate(this, R.layout.activity_main_header, null);
        userIDText = (EditText) listHeader.findViewById(R.id.userIDText);
        pwText = (EditText) listHeader.findViewById(R.id.pwText);
        decryptedText = (EditText) listHeader.findViewById(R.id.decryptedText);
        encryptedText = (EditText) listHeader.findViewById(R.id.encryptedText);
        cbCorrectPW = (CheckBox) listHeader.findViewById(R.id.correct);


        listView = (ListView) findViewById(R.id.listView);
        listView.addHeaderView(listHeader);
        listAdapter = new KeyRecyclerAdapter(this, R.id.userID);
        listView.setAdapter(listAdapter);
    }

    // refreshes the ArrayList of strings that has the userIDs
    // from the keystore
    private void refreshKeys() {
        // create a new ArrayList of strings
        userIDsInKeystore = new ArrayList<>();
        try {
            // get all the aliases from the key store
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                // for each one, add it to the arraylist...
                userIDsInKeystore.add(aliases.nextElement());
            }
        }
        catch(Exception e) {}

        if(listAdapter != null)
            listAdapter.notifyDataSetChanged();
    }

    // creates a new entry in the Keystore using the userID as the
    //  alias or key and then creates and stores public/private
    //  key info
    public void createNewKeys(View view) {
        String userID = userIDText.getText().toString();
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(userID)) {
                Calendar start = Calendar.getInstance();

                // the key (so user) will remain valid for 1 year then be deleted from the list
                //  get todays date
                Calendar end = Calendar.getInstance();
                // then add 1 year to it and store that as the end/expiration date of the alias
                end.add(Calendar.YEAR, 1);

                // Set up the KeyPairGenerator
                // the alias is in your case the user name.  It is called the alias or key in
                //  a key/value pair.  The value will be the encrypted password.
                KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(this)
                        // this is the alias or "name" of the pair
                        .setAlias(userID)
                        .setSubject(new X500Principal("CN=User Name, O=Android Authority")) // required subject
                        .setSerialNumber(BigInteger.ONE) // required serial number (just using the #1 as a BigInt for all)
                        .setStartDate(start.getTime())
                        .setEndDate(end.getTime())
                        .build();

                // Create the KeyPairGenerator using the RSA encoding algorithm
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
                generator.initialize(spec);

                // now create the key/value pair out of it.  This will have the alias or name of whatever
                //  you passed in and a blank value (in your case password) to start

                KeyPair keyPair = generator.generateKeyPair();

                // now store the encrypted pw with the clear text user ID in preferences
                SharedPreferences.Editor editor = sharedPref.edit();
                TextView tvPW = findViewById(R.id.pwText);
                editor.putString(userID, encryptString(userID,tvPW.getText().toString()));
                editor.apply();            }

        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
        refreshKeys();
    }

    public void testPassword(View view) {
        cbCorrectPW.setChecked(isCorrectPW());
    }

    private boolean isCorrectPW() {
        String userID = userIDText.getText().toString();
        try {
            // Create new key if needed
            if (!keyStore.containsAlias(userID)) {
                Toast.makeText(this, "Canbnot find user name:  " + userID, Toast.LENGTH_LONG).show();
            } else {
                // get the encrypted text from preferences for this userID
                SharedPreferences.Editor editor = sharedPref.edit();
                String encryptPW = sharedPref.getString(userID,"");
                editor.apply();

                // decrypt it and compare it with the current password
                return decryptString(userID, encryptPW).equals(pwText.getText().toString());
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // deletes a key/user from the keystore if it is there...
    public void deleteKey(final String userID) {
        AlertDialog alertDialog =new AlertDialog.Builder(this)
                .setTitle("Delete Key")
                .setMessage("Do you want to delete the key \"" + userID + "\" from the keystore?")
                .setPositiveButton("Yes", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        try {
                            // remove the ID and public/private keys from the keystore
                            keyStore.deleteEntry(userID);

                            // and remove the userID/encrypted pw from the preferences
                            SharedPreferences.Editor editor = sharedPref.edit();
                            editor.remove(userID);
                            editor.apply();

                            refreshKeys();
                        } catch (KeyStoreException e) {
                            Toast.makeText(MainActivity.this,
                                    "Exception " + e.getMessage() + " occured",
                                    Toast.LENGTH_LONG).show();
                            Log.e(TAG, Log.getStackTraceString(e));
                        }
                        dialog.dismiss();
                    }
                })
                .setNegativeButton("No", new DialogInterface.OnClickListener() {
                    public void onClick(DialogInterface dialog, int which) {
                        dialog.dismiss();
                    }
                })
                .create();
        alertDialog.show();
    }

    // encrypts the passed in string using the PUBLIC key
    // in the keystore associated with the userID
    //
    // returns the encrypted string
    public String encryptString(String userID, String pw) {
        try {

            // to encrypt the password you need to first get the private key associated with the alias (user name)
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(userID, null);

            // encryption requires both a private key and a public one so from the privateKeyEntry we just got, we ask
            // for the public key as well
            RSAPublicKey publicKey = (RSAPublicKey) privateKeyEntry.getCertificate().getPublicKey();

            // stores the text that was typed in to the "Initial Text" field here

            // make sure there is some text (in your case a password) to encrypt
            if(pw.isEmpty()) {
                Toast.makeText(this, "Enter text in the 'Initial Text' widget", Toast.LENGTH_LONG).show();
                return "";
            }

            // set up the encryption cipher
            Cipher inCipher = Cipher.getInstance(CIPHER_TYPE);

            // and initialize it with the public key we got for this alias/user name
            inCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            // create an output stream to hold the encrypted password
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

            // create a CipherOutputStream so that when we write to it, it will
            //  use the inCipher to encrpyt before writing to the outputStream
            //  in other words, write to the outputStream, but encrypt it using
            //  whatever cipher i pass in as the 2nd parameter
            CipherOutputStream cipherOutputStream = new CipherOutputStream(
                    outputStream, inCipher);

            // now write the clear text password (stored in initialText) to the cipherOutput
            // which causes it to be encrypted using the inCipher cipher we just created.
            //  and stored in the outputStream.
            cipherOutputStream.write(pw.getBytes("UTF-8"));
            cipherOutputStream.close();

            byte [] vals = outputStream.toByteArray();
            return Base64.encodeToString(vals, Base64.DEFAULT);

        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }
        return "";
    }

    // decrypts the passed in string using the PRIVATE key
    // in the keystore associated with the userID
    //
    // returns the encrypted string
    public String decryptString(String userID, String encryptPW) {
        try {
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)keyStore.getEntry(userID, null);

            Cipher output = Cipher.getInstance(CIPHER_TYPE);
            output.init(Cipher.DECRYPT_MODE, privateKeyEntry.getPrivateKey());

            // uses whatever text is in the "encrypted" edit field as the source of decryption

            CipherInputStream cipherInputStream = new CipherInputStream(
                    new ByteArrayInputStream(Base64.decode(encryptPW, Base64.DEFAULT)), output);
            ArrayList<Byte> values = new ArrayList<>();
            int nextByte;
            while ((nextByte = cipherInputStream.read()) != -1) {
                values.add((byte)nextByte);
            }

            byte[] bytes = new byte[values.size()];
            for(int i = 0; i < bytes.length; i++) {
                bytes[i] = values.get(i).byteValue();
            }

            String finalText = new String(bytes, 0, bytes.length, "UTF-8");
            return finalText;
        } catch (Exception e) {
            Toast.makeText(this, "Exception " + e.getMessage() + " occured", Toast.LENGTH_LONG).show();
            Log.e(TAG, Log.getStackTraceString(e));
        }

        return "";
    }

    // the ArrayAdapter class that deals with populating the
    //  listview in the mail layout
    public class KeyRecyclerAdapter extends ArrayAdapter<String> {

        public KeyRecyclerAdapter(Context context, int textView) {
            super(context, textView);
        }

        @Override
        public int getCount() {
            return userIDsInKeystore.size();
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View itemView = LayoutInflater.from(parent.getContext()).
                    inflate(R.layout.list_item, parent, false);

            final TextView keyAlias = (TextView) itemView.findViewById(R.id.userID);
            String userID = userIDsInKeystore.get(position);
            keyAlias.setText(userID);

            // get the encrypted text from preferences for this userID
            SharedPreferences.Editor editor = sharedPref.edit();
            String encryptPW = sharedPref.getString(userID,"");
            editor.apply();

            final TextView encryptTV = (TextView) itemView.findViewById(R.id.encryptedText);
            final TextView plainTV = (TextView) itemView.findViewById(R.id.decryptedText);

            // set the encrypted text in the view to the string retrieved from shared preferences
            encryptTV.setText(encryptPW);

            // now call decryptString on that text to get the original unencrypted password
            //  and use that one to display as the plain text/decrypted one
            plainTV.setText(decryptString(userID,encryptPW));

            final Button deleteButton = (Button) itemView.findViewById(R.id.deleteButton);
            deleteButton.setOnClickListener(new View.OnClickListener() {
                @Override
                public void onClick(View view) {
                    deleteKey(keyAlias.getText().toString());
                }
            });

            return itemView;
        }

        @Override
        public String getItem(int position) {
            return userIDsInKeystore.get(position);
        }

    }
}
