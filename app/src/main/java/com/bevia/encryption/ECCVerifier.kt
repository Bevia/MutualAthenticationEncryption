package com.bevia.encryption


import android.util.Base64
import android.util.Log
import java.security.KeyStore
import java.security.Signature

class ECCVerifier(private val keyManager: KeyGenerator) : Verifier {

    override fun verifySignature(alias: String, data: ByteArray, signatureStr: String): Boolean {
        return try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve ECC public key
            val eccPublicKey = keyStore.getCertificate(alias)?.publicKey

            if (eccPublicKey != null) {
                // Initialize the signature with the ECC public key
                val signature = Signature.getInstance("SHA256withECDSA")
                signature.initVerify(eccPublicKey)
                signature.update(data)

                // Decode the signature from Base64 and verify
                val signatureBytes = Base64.decode(signatureStr, Base64.NO_WRAP)
                signature.verify(signatureBytes)
            } else {
                Log.e("ECCVerifier", "Public key for alias '$alias' could not be retrieved.")
                false
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("ECCVerifier", "Error verifying signature: ${e.message}")
            false
        }
    }
}