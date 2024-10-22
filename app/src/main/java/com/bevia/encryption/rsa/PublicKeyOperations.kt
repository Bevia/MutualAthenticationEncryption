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
                Log.e("KeyStoreDebug", "Mistis Key with alias '$alias' not found in Keystore.")
                return
            }

            val publicKey = keyStore.getCertificate(alias)?.publicKey
            publicKey?.let {
                val publicKeyBase64 = Base64.encodeToString(it.encoded, Base64.NO_WRAP)
                Log.d("KeyStoreDebug", "Mistis RSA 2048 Public Key (Base64 Encoded):\n$publicKeyBase64")
            } ?: Log.e("KeyStoreDebug", "Mistis Public key for alias '$alias' could not be retrieved.")
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("KeyStoreDebug", "Mistis An error occurred while retrieving the public key: ${e.message}")
        }
    }

    fun generateApiKey(alias: String): String? {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            val publicKey = keyStore.getCertificate(alias)?.publicKey ?: return null
            val publicKeyBytes = publicKey.encoded
            val publicKeyHex = publicKeyBytes.joinToString("") { "%02x".format(it) }

            val sha256Digest = MessageDigest.getInstance("SHA-256")
            val hashBytes = sha256Digest.digest(publicKeyHex.toByteArray())
            hashBytes.joinToString("") { "%02x".format(it) }.also {
                Log.d("KeyStoreDebug", "Mistis Generated API Key (SHA-256 of public key): $it")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("KeyStoreDebug", "Mistis An error occurred while generating the API key: ${e.message}")
            null
        }
    }
}