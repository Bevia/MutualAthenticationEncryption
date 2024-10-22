package com.bevia.encryption.ecc


interface KeyGenerator {
    fun generateECCKeyPair(alias: String)
    fun getECCPublicKey(alias: String): String?
    fun deleteKey(alias: String) // New method to delete a key
}

interface Signer {
    fun signData(alias: String, data: ByteArray): String?
}

interface Verifier {
    fun verifySignature(alias: String, data: ByteArray, signature: String): Boolean
}
