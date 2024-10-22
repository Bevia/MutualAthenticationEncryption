import android.util.Log
import com.bevia.encryption.ecc.ECCKeyManager
import com.bevia.encryption.ecc.ECCSigner
import com.bevia.encryption.ecc.ECCVerifier
import com.bevia.encryption.rsa.KeyStoreManager
import com.bevia.encryption.rsa.PublicKeyOperations
import com.bevia.encryption.rsa.RSAEncryptor
import java.security.KeyStore

class CryptographyManager(
    private val keyStoreManager: KeyStoreManager,
    private val rsaEncryptor: RSAEncryptor,
    private val eccKeyManager: ECCKeyManager,   // Inject ECCKeyManager
    private val eccSigner: ECCSigner,
    private val eccVerifier: ECCVerifier
) {

    fun handleRSAKeyGenAndStorage(alias: String) {
        if (!keyStoreManager.doesKeyExist(alias)) {
            Log.d("Mistis CryptographyManager", "Generating RSA key pair .")
            PublicKeyOperations().printPublicKey(alias)
        } else {
            Log.d("Mistis CryptographyManager", "RSA key pair already exists.")
        }

        keyStoreManager.generateAndStoreKeyPair(alias)
        val messageToEncrypt = "Hello, Android Keystore!"
        val encryptedMessage = rsaEncryptor.encryptMessage(alias, messageToEncrypt)
        val decryptedMessage = rsaEncryptor.decryptMessage(alias, encryptedMessage)

        Log.d("Mistis CryptographyManager", "Encrypted Message: $encryptedMessage")
        Log.d("Mistis CryptographyManager", "Decrypted Message: $decryptedMessage")
    }

    fun generateECCKeyPair(alias: String) {
        eccKeyManager.generateKeyPair(alias)
    }

    fun signRSAPublicKeyWithECCPrivateKey(rsaAlias: String, eccAlias: String) {
        val keyStore = KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        val rsaPublicKey = keyStore.getCertificate(rsaAlias).publicKey.encoded

        val signature = eccSigner.signData(eccAlias, rsaPublicKey)
        signature?.let {
            val isValid = eccVerifier.verifySignature(eccAlias, rsaPublicKey, it)
            Log.d("Mistis CryptographyManager", "Signature: $it, Is valid: $isValid")
        }
    }
}