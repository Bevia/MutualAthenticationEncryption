package com.bevia.mutualathenticationencryption

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
    private lateinit var keyStoreManager: KeyStoreManagerImpl
    private lateinit var eccKeyManager: ECCKeyManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)

        setupWindowInsets()

        // Initialize key manager and cryptography components
        keyStoreManager = KeyStoreManagerImpl()
        eccKeyManager = ECCKeyManager() // Initialize ECCKeyManager

        val rsaEncryptor = RSAEncryptor(keyStoreManager)
        val eccSigner = ECCSigner(eccKeyManager) // Pass ECCKeyManager
        val eccVerifier = ECCVerifier(eccKeyManager) // Pass ECCKeyManager

        cryptographyManager = CryptographyManager(keyStoreManager, rsaEncryptor, eccKeyManager, eccSigner, eccVerifier)

        // Delete keys example
        //deleteRSAKey(getString(R.string.rsa_alias))
        //deleteECCKey(getString(R.string.ecc_alias))

        // Handle cryptographic operations
        handleCryptographicOperations()

        // Generate API Key for RSA key for authentication
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

        //PublicKeyOperations().fetchPublicKey(rsaAlias)
        // Handle RSA and ECC operations
        cryptographyManager.handleRSAKeyGenAndStorage(rsaAlias)
        cryptographyManager.generateECCKeyPair(eccAlias)

        cryptographyManager.signRSAPublicKeyWithECCPrivateKey(rsaAlias, eccAlias)
    }

    private fun deleteRSAKey(alias: String) {
        keyStoreManager.deleteKey(alias) // Call deleteKey to remove RSA key
    }

    private fun deleteECCKey(alias: String) {
        eccKeyManager.deleteKey(alias) // Call deleteKey to remove ECC key
    }
}