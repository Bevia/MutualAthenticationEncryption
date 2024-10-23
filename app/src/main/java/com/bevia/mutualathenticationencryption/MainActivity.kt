package com.bevia.mutualathenticationencryption

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.util.Log
import android.widget.Button
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import com.bevia.encryption.apikey.ApiKey
import com.bevia.encryption.ecc.ECCKeyManager
import com.bevia.encryption.ecc.ECCSigner
import com.bevia.encryption.ecc.ECCVerifier
import com.bevia.encryption.rsa.KeyStoreManagerImpl
import com.bevia.encryption.rsa.PublicKeyOperations
import com.bevia.encryption.rsa.RSAEncryptor
import java.security.MessageDigest
import java.util.UUID
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

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

        getUUID(this)

        // Set the button listener to perform cryptographic operations
        val cryptographyButton: Button = findViewById(R.id.cryptographyButton)
        cryptographyButton.setOnClickListener {
            performCryptographicOperations()

            // Generate API Key for RSA key for authentication
            ApiKey().generateApiKey(getString(R.string.rsa_alias))

            Log.d("Mistis MainActivity", "Generated fingerprint:  " + generateDeviceFingerprint())
        }
    }

    private fun generateDeviceFingerprint(): String {
        val deviceInfo = "Brand:${Build.BRAND}, Model:${Build.MODEL}, " +
                "Manufacturer:${Build.MANUFACTURER}, Version:${Build.VERSION.SDK_INT}, " +
                "Hardware:${Build.HARDWARE}"

        // Hash the device info to create a fingerprint
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(deviceInfo.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }
    }

    private fun getUUID(context: Context): String {
        val sharedPreferences: SharedPreferences =
            context.getSharedPreferences("AppPreferences", Context.MODE_PRIVATE)
        var uuid = sharedPreferences.getString("UUID", null)

        if (uuid == null) {
            uuid = UUID.randomUUID().toString()
            sharedPreferences.edit().putString("UUID", uuid).apply()
        }

        Log.d("Mistis UUID", "getUUID: $uuid")

        return uuid
    }


    fun generateHmac(data: String, secret: String): String {
        val secretKeySpec = SecretKeySpec(secret.toByteArray(), "HmacSHA256")
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(secretKeySpec)
        val hmacBytes = mac.doFinal(data.toByteArray())
        return hmacBytes.joinToString("") { "%02x".format(it) }
    }

    private fun performCryptographicOperations() {
        // cryptographyManager is initialized lazily, so no need to check explicitly
        cryptographyManager.handleRSAKeyGenAndStorage(getString(R.string.rsa_alias))
        cryptographyManager.generateECCKeyPair(getString(R.string.ecc_alias))
        cryptographyManager.signRSAPublicKeyWithECCPrivateKey(getString(R.string.rsa_alias), getString(R.string.ecc_alias))

        PublicKeyOperations().fetchPublicKey(getString(R.string.rsa_alias))
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