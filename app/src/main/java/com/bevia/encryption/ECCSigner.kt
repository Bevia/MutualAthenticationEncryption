package com.bevia.encryption

import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.Signature

class ECCSigner(private val keyManager: KeyGenerator) : Signer {

    override fun signData(alias: String, data: ByteArray): String? {
        return try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve ECC private key
            val eccPrivateKey = keyStore.getKey(alias, null) as java.security.PrivateKey

            // Initialize the signature with the ECC private key
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(eccPrivateKey)
            signature.update(data)

            // Sign the data and return the signature as Base64
            val signedData = signature.sign()
            Base64.encodeToString(signedData, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("ECCSigner", "Error signing data: ${e.message}")
            null
        }
    }
}