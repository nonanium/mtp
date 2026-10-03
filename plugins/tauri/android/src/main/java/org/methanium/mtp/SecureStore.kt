package org.methanium.mtp

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal object SecureStore {
    private const val alias = "mtp-native-config-v1"
    private fun preferences(context: Context) = context.getSharedPreferences(alias, Context.MODE_PRIVATE)
    @Synchronized private fun key(create: Boolean = true): SecretKey {
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (store.getKey(alias, null) as? SecretKey)?.let { return it }
        check(create) { "MTP keystore key is missing" }
        return KeyGenerator.getInstance("AES", "AndroidKeyStore").apply {
            init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build())
        }.generateKey()
    }
    fun save(context: Context, config: String) {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key())
        cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
        val payload = cipher.iv + cipher.doFinal(config.toByteArray(Charsets.UTF_8))
        check(preferences(context).edit().putString("config", Base64.encodeToString(payload, Base64.NO_WRAP)).commit())
    }
    fun load(context: Context): String? {
        val payload = preferences(context).getString("config", null) ?: return null
        val bytes = Base64.decode(payload, Base64.NO_WRAP)
        require(bytes.size >= 28)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key(false), GCMParameterSpec(128, bytes.copyOfRange(0, 12)))
        cipher.updateAAD(alias.toByteArray(Charsets.UTF_8))
        return String(cipher.doFinal(bytes.copyOfRange(12, bytes.size)), Charsets.UTF_8)
    }
    fun enabled(context: Context) = preferences(context).getBoolean("enabled", false)
    fun setEnabled(context: Context, enabled: Boolean) {
        check(preferences(context).edit().putBoolean("enabled", enabled).commit())
    }
    fun clear(context: Context) {
        check(preferences(context).edit().clear().commit())
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(alias)
    }
}
