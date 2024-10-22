package com.bevia.encryption.rsa

import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.MessageDigest

class PublicKeyOperations {

    fun fetchPublicKey(alias: String) {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (!keyStore.containsAlias(alias)) {
                Log.e("Mistis KeyStoreDebug", " Key with alias '$alias' not found in Keystore.")
                return
            }

            val publicKey = keyStore.getCertificate(alias)?.publicKey
            publicKey?.let {
                val publicKeyBase64 = Base64.encodeToString(it.encoded, Base64.NO_WRAP)
                Log.d("Mistis KeyStoreDebug", " RSA 2048 Public Key (Base64 Encoded):\n$publicKeyBase64")
            } ?: Log.e("Mistis KeyStoreDebug", " Public key for alias '$alias' could not be retrieved.")
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis KeyStoreDebug", " An error occurred while retrieving the public key: ${e.message}")
        }
    }
}