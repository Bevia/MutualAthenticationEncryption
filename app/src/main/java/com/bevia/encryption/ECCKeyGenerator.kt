package com.bevia.encryption


interface KeyGenerator {
    fun generateKeyPair(alias: String)
    fun getPublicKey(alias: String): String?
}

interface Signer {
    fun signData(alias: String, data: ByteArray): String?
}

interface Verifier {
    fun verifySignature(alias: String, data: ByteArray, signature: String): Boolean
}
