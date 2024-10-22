package com.bevia.encryption.ecc

import java.security.KeyStore
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator


class ECCKeyManager : KeyGenerator {

    override fun generateECCKeyPair(alias: String) {
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

            Log.d("Mistis ECCKeyManager", "ECC P-256 key pair generated and stored successfully.")

            // Verify that the key has been stored
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (keyStore.containsAlias(alias)) {
                Log.d("Mistis ECCKeyManager", "Key with alias '$alias' exists in the Keystore.")
            } else {
                Log.e("Mistis ECCKeyManager", "Key with alias '$alias' was not found in the Keystore.")
            }

        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis ECCKeyManager", "Error generating ECC key pair: ${e.message}")
        }
    }

    override fun getECCPublicKey(alias: String): String? {
        return try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Check if the alias exists in the Keystore
            if (!keyStore.containsAlias(alias)) {
                Log.e("Mistis ECCKeyManager", "Key with alias '$alias' not found in Keystore.")
                return null
            }

            // Retrieve the public key using the alias
            val publicKey = keyStore.getCertificate(alias)?.publicKey

            if (publicKey != null) {
                // Convert the public key to Base64 string for easy return
                val publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)

                // Log or print the public key
                Log.d("Mistis ECCKeyManager", "Public Key for alias '$alias': $publicKeyBase64")
                println("Mistis Public Key (Base64 Encoded): $publicKeyBase64")

                return publicKeyBase64
            } else {
                Log.e("Mistis ECCKeyManager", "Public key for alias '$alias' could not be retrieved.")
                return null
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis ECCKeyManager", "An error occurred while retrieving the ECC public key: ${e.message}")
            return null
        }
    }

    override fun deleteKey(alias: String) {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias) // Deletes the ECC key entry
                Log.d("Mistis ECCKeyManager", "ECC key with alias '$alias' deleted successfully.")
            } else {
                Log.e("Mistis ECCKeyManager", "ECC key with alias '$alias' does not exist.")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis ECCKeyManager", "Error deleting ECC key with alias '$alias': ${e.message}")
        }
    }
}