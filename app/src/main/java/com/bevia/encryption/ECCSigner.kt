package com.bevia.encryption

class ECCSigner(private val keyManager: KeyGenerator) : Signer {
    override fun signData(alias: String, data: ByteArray): String? {
        // Signing logic here using the keyManager to get the private key
    }
}