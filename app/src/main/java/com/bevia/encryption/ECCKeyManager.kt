package com.bevia.encryption

import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator


class ECCKeyManager : KeyGenerator {

    override fun generateKeyPair(alias: String) {
        try {
            // Create a KeyPairGenerator for EC (Elliptic Curve)
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )

            // Configure the key pair generator
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build()

            // Initialize and generate the key pair
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()

            Log.d("ECCKeyManager", "ECC P-256 key pair generated and stored successfully.")
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("ECCKeyManager", "Error generating ECC key pair: ${e.message}")
        }
    }

    override fun getPublicKey(alias: String): String? {
        return try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Check if the alias exists in the Keystore
            if (!keyStore.containsAlias(alias)) {
                Log.e("ECCKeyManager", "Key with alias '$alias' not found in Keystore.")
                return null
            }

            // Retrieve the public key using the alias
            val publicKey = keyStore.getCertificate(alias)?.publicKey

            if (publicKey != null) {
                // Convert the public key to Base64 string for easy return
                return Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)
            } else {
                Log.e("ECCKeyManager", "Public key for alias '$alias' could not be retrieved.")
                return null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("ECCKeyManager", "An error occurred while retrieving the ECC public key: ${e.message}")
            return null
        }
    }
}