package com.bevia.encryption


class ECCKeyManager : KeyGenerator {
    override fun generateKeyPair(alias: String) {
        // Key generation logic here
    }

    override fun getPublicKey(alias: String): String? {
        // Key retrieval logic here
        return publicKeyBase64
    }
}