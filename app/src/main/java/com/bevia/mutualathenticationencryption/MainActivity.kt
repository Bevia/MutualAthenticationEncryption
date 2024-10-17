package com.bevia.mutualathenticationencryption

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.bevia.encryption.ECCKeyGenStored
import com.bevia.encryption.RSAKeyPairGenStored
import java.security.KeyStore

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun testingRSAKeyGenAndStorage() {
        val alias = "mistis"

        if (!RSAKeyPairGenStored().doesKeyExist(alias)) {

            // Step 1: Generate and store the key pair in Keystore
            RSAKeyPairGenStored().generateAndStoreKeyPair(alias)

            // Step 2: Encrypt a message using the public key
            val messageToEncrypt = "Hello, Android Keystore!"
            val encryptedMessage = RSAKeyPairGenStored().encryptMessage(alias, messageToEncrypt)
            println("Mistis Encrypted Message: $encryptedMessage")
            // Step 3: Decrypt the message using the private key
            val decryptedMessage = RSAKeyPairGenStored().decryptMessage(alias, encryptedMessage)
            println("Mistis Decrypted Message: $decryptedMessage")
            // Print the public key for the given alias
            RSAKeyPairGenStored().printPublicKey(alias)
            Toast.makeText(
                this,
                "Key pair with alias $alias created successfully.",
                Toast.LENGTH_SHORT
            )
                .show()
            println("Key pair with alias $alias created successfully.")
        } else {
            // Update the UI to reflect the deletion
            Log.d("KeyStoreDebug", "RSA key pair already exists. Skipping key generation.")
        }
    }

    private fun signRSAPublicKeyWithECCPrivateKey(rsaAlia: String, eccAlias: String) {

        // Step 2: Retrieve the RSA public key (in bytes) to sign it
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val rsaPublicKey = keyStore.getCertificate(rsaAlia).publicKey.encoded

        val signature = ECCKeyGenStored().signDataWithECCPrivateKey(eccAlias, rsaPublicKey)
        Log.d("Mistis KeyStoreDebug", "Signature (Base64): $signature")

        val isVerified =
            ECCKeyGenStored().verifySignatureWithECCPublicKey(eccAlias, rsaPublicKey, signature!!)
        Log.d("Mistis KeyStoreDebug", "Signature verified: $isVerified")

    }

    private fun generateECCKeyPairAndStore() {
        val alias = "ecc_keys"

        // Step 1: Generate and store the ECC key pair in Keystore
        ECCKeyGenStored().generateAndStoreECCKeyPair(alias)

        // Step 2: Print the ECC public key for the given alias
        ECCKeyGenStored().printECCPublicKey(alias)
    }

}