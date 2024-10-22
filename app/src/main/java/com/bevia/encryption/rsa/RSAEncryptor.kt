package com.bevia.encryption.rsa

import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher

class RSAEncryptor(private val keyStoreManager: KeyStoreManager) {

    fun encryptMessage(alias: String, message: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val publicKey = keyStore.getCertificate(alias).publicKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)

        val encryptedBytes = cipher.doFinal(message.toByteArray())
        return Base64.encodeToString(encryptedBytes, Base64.DEFAULT)
    }

    fun decryptMessage(alias: String, encryptedMessage: String): String {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)

        val privateKey = keyStore.getKey(alias, null)
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)

        val encryptedBytes = Base64.decode(encryptedMessage, Base64.DEFAULT)
        val decryptedBytes = cipher.doFinal(encryptedBytes)
        return String(decryptedBytes)
    }
}