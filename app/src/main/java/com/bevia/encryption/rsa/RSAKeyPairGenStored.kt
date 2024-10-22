package com.bevia.encryption.rsa

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.RSAKeyGenParameterSpec
import javax.crypto.Cipher

class RSAKeyPairGenStored {

    // Function to check if the RSA key pair exists
    fun doesKeyExist(alias: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.containsAlias(alias)
    }

    fun generateAndStoreKeyPair(alias: String) {
        // Create a KeyPairGenerator for RSA
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )

        // Configure the key pair generator
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setAlgorithmParameterSpec(
                RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)  // Use the correct RSAKeyGenParameterSpec
            )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .build()

        // Initialize and generate the key pair
        keyPairGenerator.initialize(keyGenParameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    fun encryptMessage(alias: String, message: String): String {
        // Load the Android Keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        // Get the public key from the Keystore
        val publicKey = keyStore.getCertificate(alias).publicKey

        // Initialize the Cipher for encryption with RSA
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        // Encrypt the message and return as Base64 string
        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptMessage(alias: String, encryptedMessage: String): String {
        // Load the Android Keystore
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        // Get the private key from the Keystore
        val privateKey = keyStore.getKey(alias, null)

        // Initialize the Cipher for decryption with RSA
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        // Decrypt the message and return as plain text
        val encryptedBytes = Base64.decode(encryptedMessage, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }

    fun printPublicKey(alias: String) {
        try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Check if the alias exists in the Keystore
            if (!keyStore.containsAlias(alias)) {
                Log.e("KeyStoreDebug", "Mistis Key with alias '$alias' not found in Keystore.")
                return
            }

            // Retrieve the public key using the alias
            val publicKey = keyStore.getCertificate(alias)?.publicKey

            if (publicKey != null) {
                // Convert the public key to Base64 string for easy printing
                val publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)

                // Log the Base64-encoded public key for debugging
                Log.d("KeyStoreDebug", "Mistis RSA 2048 Public Key (Base64 Encoded):\n$publicKeyBase64")
            } else {
                Log.e("KeyStoreDebug", "Mistis Public key for alias '$alias' could not be retrieved.")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("KeyStoreDebug", "Mistis An error occurred while retrieving the public key: ${e.message}")
        }
    }
}