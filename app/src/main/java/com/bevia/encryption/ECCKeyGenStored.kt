package com.bevia.encryption

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature

class ECCKeyGenStored {


    fun generateAndStoreECCKeyPair(alias: String) {
        try {
            // Create a KeyPairGenerator for EC (Elliptic Curve)
            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
            )

            // Configure the key pair generator
            val keyGenParameterSpec = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY  // ECC is generally used for signing and verifying
            )
                .setDigests(KeyProperties.DIGEST_SHA256)  // Digest for signing
                .build()

            // Initialize and generate the key pair
            keyPairGenerator.initialize(keyGenParameterSpec)
            keyPairGenerator.generateKeyPair()

            Log.d("Mistis KeyStoreDebug", "ECC P-256 key pair generated and stored successfully.")
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis KeyStoreDebug", "Error generating ECC key pair: ${e.message}")
        }
    }

    fun printECCPublicKey(alias: String) {
        try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Check if the alias exists in the Keystore
            if (!keyStore.containsAlias(alias)) {
                Log.e("Mistis KeyStoreDebug", "Key with alias '$alias' not found in Keystore.")
                return
            }

            // Retrieve the public key using the alias
            val publicKey = keyStore.getCertificate(alias)?.publicKey

            if (publicKey != null) {
                // Convert the public key to Base64 string for easy printing
                val publicKeyBase64 = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP)

                // Log the Base64-encoded public key for debugging
                Log.d("Mistis KeyStoreDebug", "ECC Public Key (Base64 Encoded):\n$publicKeyBase64")
            } else {
                Log.e("Mistis KeyStoreDebug", "Public key for alias '$alias' could not be retrieved.")
            }
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("Mistis KeyStoreDebug", "An error occurred while retrieving the ECC public key: ${e.message}")
        }
    }

    fun signDataWithECCPrivateKey(eccAlias: String, rsaPublicKey: ByteArray): String? {
        try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve ECC private key
            val eccPrivateKey = keyStore.getKey(eccAlias, null) as java.security.PrivateKey

            // Initialize the signature with the ECC private key
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initSign(eccPrivateKey)
            signature.update(rsaPublicKey)

            // Sign the RSA public key and return the signature as Base64
            val signedData = signature.sign()
            return Base64.encodeToString(signedData, Base64.NO_WRAP)
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("KeyStoreDebug", "Error signing data: ${e.message}")
            return null
        }
    }

    fun verifySignatureWithECCPublicKey(eccAlias: String, rsaPublicKey: ByteArray, signatureStr: String): Boolean {
        try {
            // Load the Android Keystore
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            // Retrieve ECC public key
            val eccPublicKey = keyStore.getCertificate(eccAlias).publicKey

            // Initialize the signature with the ECC public key
            val signature = Signature.getInstance("SHA256withECDSA")
            signature.initVerify(eccPublicKey)
            signature.update(rsaPublicKey)

            // Verify the signature
            val signatureBytes = Base64.decode(signatureStr, Base64.NO_WRAP)
            return signature.verify(signatureBytes)
        } catch (e: Exception) {
            e.printStackTrace()
            Log.e("KeyStoreDebug", "Error verifying signature: ${e.message}")
            return false
        }
    }
}