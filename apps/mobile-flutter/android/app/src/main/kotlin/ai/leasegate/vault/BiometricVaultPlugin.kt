package ai.leasegate.vault

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Biometric-gated, Keystore-backed cache of one vault master password. */
class BiometricVaultPlugin(private val activity: MainActivity) : MethodChannel.MethodCallHandler {
    private val preferences = activity.getSharedPreferences("biometric_vaults", 0)
    private var prompt: BiometricPrompt? = null

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "isAvailable" -> result.success(canAuthenticate())
            "hasCredential" -> result.success(hasCredential(requireVaultId(call, result) ?: return))
            "enable" -> {
                val vaultId = requireVaultId(call, result) ?: return
                val password = call.argument<String>("password")
                if (password.isNullOrEmpty()) {
                    result.error("invalid_request", "password is required", null)
                    return
                }
                enable(vaultId, password, result)
            }
            "unlock" -> unlock(requireVaultId(call, result) ?: return, result)
            "disable" -> {
                disable(requireVaultId(call, result) ?: return)
                result.success(true)
            }
            else -> result.notImplemented()
        }
    }

    private fun requireVaultId(call: MethodCall, result: MethodChannel.Result): String? {
        val value = call.argument<String>("vault_id")?.trim()
        if (value.isNullOrEmpty()) result.error("invalid_request", "vault_id is required", null)
        return value?.takeIf { it.isNotEmpty() }
    }

    private fun canAuthenticate(): Boolean = BiometricManager.from(activity).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG,
    ) == BiometricManager.BIOMETRIC_SUCCESS

    private fun hasCredential(vaultId: String): Boolean =
        preferences.contains("$vaultId.ciphertext") && preferences.contains("$vaultId.iv")

    private fun enable(vaultId: String, password: String, result: MethodChannel.Result) {
        if (!canAuthenticate()) {
            result.error("biometric_unavailable", "Strong biometric authentication is unavailable", null)
            return
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(vaultId))
            authenticate(cipher, "Enable biometric unlock", result) { authenticated ->
                val encrypted = authenticated.doFinal(password.toByteArray(Charsets.UTF_8))
                preferences.edit()
                    .putString("$vaultId.ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                    .putString("$vaultId.iv", Base64.encodeToString(authenticated.iv, Base64.NO_WRAP))
                    .apply()
                result.success(true)
            }
        } catch (error: Exception) {
            disable(vaultId)
            result.error("biometric_failed", "Biometric enrollment could not be completed", null)
        }
    }

    private fun unlock(vaultId: String, result: MethodChannel.Result) {
        val encrypted = preferences.getString("$vaultId.ciphertext", null)
        val iv = preferences.getString("$vaultId.iv", null)
        if (encrypted == null || iv == null) {
            result.error("not_found", "Biometric unlock is not enabled for this vault", null)
            return
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getKey(vaultId),
                GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)),
            )
            authenticate(cipher, "Unlock Leasegate Vault", result) { authenticated ->
                val clear = authenticated.doFinal(Base64.decode(encrypted, Base64.NO_WRAP))
                try {
                    result.success(String(clear, Charsets.UTF_8))
                } finally {
                    clear.fill(0)
                }
            }
        } catch (error: KeyPermanentlyInvalidatedException) {
            disable(vaultId)
            result.error("biometric_invalidated", "Biometrics changed; enter the master password again", null)
        } catch (error: Exception) {
            result.error("biometric_failed", "Biometric unlock failed", null)
        }
    }

    private fun authenticate(
        cipher: Cipher,
        title: String,
        result: MethodChannel.Result,
        success: (Cipher) -> Unit,
    ) {
        val executor = ContextCompat.getMainExecutor(activity)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                prompt = null
                val authenticated = auth.cryptoObject?.cipher
                if (authenticated == null) {
                    result.error("biometric_failed", "No authenticated cipher was returned", null)
                    return
                }
                try {
                    success(authenticated)
                } catch (_: Exception) {
                    result.error("biometric_failed", "The protected credential could not be processed", null)
                }
            }

            override fun onAuthenticationError(code: Int, message: CharSequence) {
                prompt = null
                result.error("biometric_cancelled", message.toString(), null)
            }
        }
        prompt = BiometricPrompt(activity, executor, callback).also {
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("Authenticate with a strong biometric")
                .setNegativeButtonText("Use master password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            it.authenticate(info, BiometricPrompt.CryptoObject(cipher))
        }
    }

    private fun alias(vaultId: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(vaultId.toByteArray(Charsets.UTF_8))
        return "leasegate.biometric." + digest.take(12).joinToString("") { "%02x".format(it) }
    }

    private fun getKey(vaultId: String): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        return store.getKey(alias(vaultId), null) as SecretKey
    }

    private fun getOrCreateKey(vaultId: String): SecretKey {
        try {
            return getKey(vaultId)
        } catch (_: Exception) {
            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            val builder = KeyGenParameterSpec.Builder(
                alias(vaultId),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setUserAuthenticationRequired(true)
                .setInvalidatedByBiometricEnrollment(true)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
            generator.init(builder.build())
            return generator.generateKey()
        }
    }

    private fun disable(vaultId: String) {
        preferences.edit().remove("$vaultId.ciphertext").remove("$vaultId.iv").apply()
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias(vaultId))
        } catch (_: Exception) { }
    }

    companion object {
        const val CHANNEL = "com.keylease/biometric"
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
