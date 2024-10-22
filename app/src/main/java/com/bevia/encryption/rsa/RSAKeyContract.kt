package com.bevia.encryption.rsa

interface RSAKeyContract {

    fun generateKeyPair(alias: String)
    fun getPublicKey(alias: String): String?
}