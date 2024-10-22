package com.bevia.encryption.apikey

import android.util.Log
import java.security.KeyStore
import java.security.MessageDigest

class ApiKey {

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
                Log.d("Mistis KeyStoreDebug", " Generated API Key (SHA-256 of public key): $it")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis KeyStoreDebug", " An error occurred while generating the API key: ${e.message}")
            null
        }
    }
}