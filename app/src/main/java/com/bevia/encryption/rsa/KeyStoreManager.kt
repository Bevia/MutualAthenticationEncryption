package com.bevia.encryption.rsa

interface KeyStoreManager {
    fun doesKeyExist(alias: String): Boolean
    fun generateAndStoreKeyPair(alias: String)
}
