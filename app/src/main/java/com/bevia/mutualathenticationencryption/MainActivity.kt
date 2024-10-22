package com.bevia.mutualathenticationencryption

import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.bevia.encryption.apikey.ApiKey
import com.bevia.encryption.ecc.ECCKeyManager
import com.bevia.encryption.ecc.ECCSigner
import com.bevia.encryption.ecc.ECCVerifier
import com.bevia.encryption.rsa.KeyStoreManagerImpl
import com.bevia.encryption.rsa.RSAEncryptor

class MainActivity : AppCompatActivity() {

    private val keyStoreManager: KeyStoreManagerImpl by lazy {
        KeyStoreManagerImpl()
    }

    private val eccKeyManager: ECCKeyManager by lazy {
        ECCKeyManager()
    }

    private val cryptographyManager: CryptographyManager by lazy {
        // Initialize only when accessed
        val rsaEncryptor = RSAEncryptor(keyStoreManager)
        val eccSigner = ECCSigner(eccKeyManager)
        val eccVerifier = ECCVerifier(eccKeyManager)

        CryptographyManager(keyStoreManager, rsaEncryptor, eccKeyManager, eccSigner, eccVerifier)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        setupWindowInsets()

        performCryptographicOperations()

        // Generate API Key for RSA key for authentication
        ApiKey().generateApiKey(getString(R.string.rsa_alias))
    }

    private fun performCryptographicOperations() {
        // cryptographyManager is initialized lazily, so no need to check explicitly
        cryptographyManager.handleRSAKeyGenAndStorage(getString(R.string.rsa_alias))
        cryptographyManager.generateECCKeyPair(getString(R.string.ecc_alias))
        cryptographyManager.signRSAPublicKeyWithECCPrivateKey(getString(R.string.rsa_alias), getString(R.string.ecc_alias))
    }

    private fun setupWindowInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun deleteRSAKey(alias: String) {
        keyStoreManager.deleteKey(alias) // Call deleteKey to remove RSA key
    }

    private fun deleteECCKey(alias: String) {
        eccKeyManager.deleteKey(alias) // Call deleteKey to remove ECC key
    }
}