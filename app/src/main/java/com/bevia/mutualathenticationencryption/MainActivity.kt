package com.bevia.mutualathenticationencryption

import CryptographyManager
import android.os.Bundle
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.bevia.encryption.ecc.ECCKeyManager
import com.bevia.encryption.ecc.ECCSigner
import com.bevia.encryption.ecc.ECCVerifier
import com.bevia.encryption.rsa.KeyStoreManagerImpl
import com.bevia.encryption.rsa.PublicKeyOperations
import com.bevia.encryption.rsa.RSAEncryptor

class MainActivity : AppCompatActivity() {

    private lateinit var cryptographyManager: CryptographyManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        setupWindowInsets()

        // Initialize key manager and cryptography components
        val keyStoreManager = KeyStoreManagerImpl()
        val rsaEncryptor = RSAEncryptor(keyStoreManager)
        val eccKeyManager = ECCKeyManager() // Initialize ECCKeyManager
        val eccSigner = ECCSigner(eccKeyManager) // Pass ECCKeyManager
        val eccVerifier = ECCVerifier(eccKeyManager) // Pass ECCKeyManager

        cryptographyManager = CryptographyManager(keyStoreManager, rsaEncryptor, eccKeyManager, eccSigner, eccVerifier)

        handleCryptographicOperations()

        // Generate API Key for RSA key
        PublicKeyOperations().generateApiKey(getString(R.string.rsa_alias))
    }

    private fun setupWindowInsets() {
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }
    }

    private fun handleCryptographicOperations() {
        val rsaAlias = getString(R.string.rsa_alias)
        val eccAlias = getString(R.string.ecc_alias)

        // Handle RSA and ECC operations
        cryptographyManager.handleRSAKeyGenAndStorage(rsaAlias)
        cryptographyManager.generateECCKeyPair(eccAlias)
        cryptographyManager.signRSAPublicKeyWithECCPrivateKey(rsaAlias, eccAlias)
    }
}