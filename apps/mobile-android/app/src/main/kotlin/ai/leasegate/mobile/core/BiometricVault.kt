package ai.leasegate.mobile.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Biometric-gated, Keystore-backed cache of one vault master password per
 * vault. Direct port of `BiometricVaultPlugin.kt`, minus the MethodChannel:
 * the AES-GCM key requires auth-per-use, is held in `AndroidKeyStore`, and is
 * invalidated when biometric enrollment changes. The owner token continues
 * to live only in Rust memory and is never persisted.
 */
class BiometricVault(private val activity: FragmentActivity) {
    private val preferences = activity.getSharedPreferences("biometric_vaults", 0)

    fun isAvailable(): Boolean = BiometricManager.from(activity).canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG,
    ) == BiometricManager.BIOMETRIC_SUCCESS

    fun hasCredential(vaultId: String): Boolean =
        preferences.contains("$vaultId.ciphertext") && preferences.contains("$vaultId.iv")

    suspend fun enable(vaultId: String, password: String) {
        if (!isAvailable()) {
            throw KeyLeaseException(
                "Strong biometric authentication is unavailable",
                KeyLeaseErrorCode.CLIENT,
            )
        }
        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey(vaultId))
            val authenticated = authenticate(cipher, "Enable biometric unlock")
            val encrypted = authenticated.doFinal(password.toByteArray(Charsets.UTF_8))
            preferences.edit()
                .putString("$vaultId.ciphertext", Base64.encodeToString(encrypted, Base64.NO_WRAP))
                .putString("$vaultId.iv", Base64.encodeToString(authenticated.iv, Base64.NO_WRAP))
                .apply()
        } catch (error: BiometricCancelled) {
            throw error
        } catch (error: Exception) {
            disable(vaultId)
            throw KeyLeaseException(
                "Biometric enrollment could not be completed",
                KeyLeaseErrorCode.CLIENT,
            )
        }
    }

    /** Returns the cached password, or null if the prompt was cancelled. */
    suspend fun unlock(vaultId: String): String? {
        val encrypted = preferences.getString("$vaultId.ciphertext", null)
        val iv = preferences.getString("$vaultId.iv", null)
            ?: throw KeyLeaseException(
                "Biometric unlock is not enabled for this vault",
                KeyLeaseErrorCode.NOT_FOUND,
            )
        if (encrypted == null) {
            throw KeyLeaseException(
                "Biometric unlock is not enabled for this vault",
                KeyLeaseErrorCode.NOT_FOUND,
            )
        }
        return try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                getKey(vaultId),
                GCMParameterSpec(128, Base64.decode(iv, Base64.NO_WRAP)),
            )
            val authenticated = authenticate(cipher, "Unlock Leasegate Vault")
            val clear = authenticated.doFinal(Base64.decode(encrypted, Base64.NO_WRAP))
            try {
                String(clear, Charsets.UTF_8)
            } finally {
                clear.fill(0)
            }
        } catch (error: BiometricCancelled) {
            null
        } catch (error: KeyPermanentlyInvalidatedException) {
            disable(vaultId)
            throw KeyLeaseException(
                "Biometrics changed; enter the master password again",
                KeyLeaseErrorCode.CLIENT,
            )
        } catch (error: Exception) {
            throw KeyLeaseException("Biometric unlock failed", KeyLeaseErrorCode.CLIENT)
        }
    }

    fun disable(vaultId: String) {
        preferences.edit().remove("$vaultId.ciphertext").remove("$vaultId.iv").apply()
        try {
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                .deleteEntry(alias(vaultId))
        } catch (_: Exception) {
        }
    }

    private class BiometricCancelled(message: String) : Exception(message)

    private suspend fun authenticate(cipher: Cipher, title: String): Cipher =
        suspendCancellableCoroutine { continuation ->
            val executor = ContextCompat.getMainExecutor(activity)
            var prompt: BiometricPrompt? = null
            val callback = object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                    val authenticated = auth.cryptoObject?.cipher
                    if (authenticated == null) {
                        continuation.resumeWithException(
                            KeyLeaseException(
                                "No authenticated cipher was returned",
                                KeyLeaseErrorCode.CLIENT,
                            ),
                        )
                        return
                    }
                    continuation.resume(authenticated)
                }

                override fun onAuthenticationError(code: Int, message: CharSequence) {
                    continuation.resumeWithException(BiometricCancelled(message.toString()))
                }
            }
            prompt = BiometricPrompt(activity, executor, callback)
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setSubtitle("Authenticate with a strong biometric")
                .setNegativeButtonText("Use master password")
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
                .build()
            prompt.authenticate(info, BiometricPrompt.CryptoObject(cipher))
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
        return try {
            getKey(vaultId)
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
            generator.generateKey()
        }
    }

    companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
