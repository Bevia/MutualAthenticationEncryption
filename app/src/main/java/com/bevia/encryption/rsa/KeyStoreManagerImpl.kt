package com.bevia.encryption.rsa

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.RSAKeyGenParameterSpec

class KeyStoreManagerImpl : KeyStoreManager {

    override fun doesKeyExist(alias: String): Boolean {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        return keyStore.containsAlias(alias)
    }

    override fun generateAndStoreKeyPair(alias: String) {
        val keyPairGenerator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore"
        )
        val keyGenParameterSpec = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setAlgorithmParameterSpec(
                RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4)
            )
            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
            .build()

        keyPairGenerator.initialize(keyGenParameterSpec)
        keyPairGenerator.generateKeyPair()
    }

    override fun deleteKey(alias: String) {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias) // Deletes the key entry from the Keystore
                Log.d("Mistis KeyStoreManagerImpl", "Key with alias '$alias' deleted successfully.")
            } else {
                Log.e("Mistis KeyStoreManagerImpl", "Key with alias '$alias' does not exist.")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis KeyStoreManagerImpl", "Error deleting key with alias '$alias': ${e.message}")
        }
    }
}
