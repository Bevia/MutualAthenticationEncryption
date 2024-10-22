package com.bevia.mutualathenticationencryption

import android.os.Bundle
import android.util.Log
import android.widget.Toast
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.bevia.encryption.ecc.ECCKeyManager
import com.bevia.encryption.ecc.ECCSigner
import com.bevia.encryption.ecc.ECCVerifier
import com.bevia.encryption.rsa.KeyStoreManagerImpl
import com.bevia.encryption.rsa.PublicKeyOperations
import com.bevia.encryption.rsa.RSAEncryptor
import java.security.KeyStore

class MainActivity : AppCompatActivity() {

    val keyManager = ECCKeyManager()
    val signer = ECCSigner(keyManager)
    val verifier = ECCVerifier(keyManager)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        testingRSAKeyGenAndStorage()
        generateECCKeyPairAndStore()
        signRSAPublicKeyWithECCPrivateKey(getString(R.string.rsa_alias), getString(R.string.ecc_alias))

        // Step 1: Create an instance of KeyStoreManagerImpl

        PublicKeyOperations().generateApiKey(getString(R.string.rsa_alias))
        //RSAKeyPairGenStored().generateApiKey(getString(R.string.rsa_alias))

    }

    private fun testingRSAKeyGenAndStorage() {
        val alias = getString(R.string.rsa_alias)
        val keyStoreManager = KeyStoreManagerImpl()
        val rsaEncryptor = RSAEncryptor(keyStoreManager)

        if (!keyStoreManager.doesKeyExist(alias)) {

            // Step 1: Generate and store the key pair in Keystore
            keyStoreManager.generateAndStoreKeyPair(alias)

            // Step 2: Encrypt a message using the public key
            val messageToEncrypt = "Hello, Android Keystore!"
            val encryptedMessage = rsaEncryptor.encryptMessage(alias, messageToEncrypt)
            println("Mistis Encrypted Message: $encryptedMessage")
            // Step 3: Decrypt the message using the private key
            val decryptedMessage = rsaEncryptor.decryptMessage(alias, encryptedMessage)
            println("Mistis Decrypted Message: $decryptedMessage")
            // Print the public key for the given alias
            PublicKeyOperations().printPublicKey(alias)
            Toast.makeText(
                this,
                "Key pair with alias $alias created successfully.",
                Toast.LENGTH_SHORT
            )
                .show()
            println("Mistis Key pair with alias $alias created successfully.")
        } else {
            // Update the UI to reflect the deletion
            Log.d("Mistis KeyStoreDebug", "RSA key pair already exists. Skipping key generation.")
        }
    }

    private fun signRSAPublicKeyWithECCPrivateKey(rsaAlia: String, eccAlias: String) {

        // Step 2: Retrieve the RSA public key (in bytes) to sign it
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val rsaPublicKey = keyStore.getCertificate(rsaAlia).publicKey.encoded

        // Sign the data
        val signature = signer.signData(eccAlias, rsaPublicKey)
        if (signature != null) {
            Log.d("Mistis", "Signature: $signature")

            // Verify the signature
            val isValid = verifier.verifySignature(eccAlias, rsaPublicKey, signature)
            Log.d("Mistis", "Is signature valid? $isValid")
        }

    }

    private fun generateECCKeyPairAndStore() {
        // Step 1: Generate and store the ECC key pair in Keystore
        // Generate ECC Key Pair
        keyManager.generateKeyPair(getString(R.string.ecc_alias))
    }

}