package org.nonanium.mtp

import android.app.Activity
import app.tauri.annotation.Command
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Plugin
import app.tauri.plugin.Invoke
import app.tauri.annotation.InvokeArg

@InvokeArg
class MtpConfig {
    var nativeLibrary: String? = null
}

@TauriPlugin
class MtpPlugin(private val activity: Activity) : Plugin(activity) {
    override fun load(webView: android.webkit.WebView) {
        MtpService.attach(activity)
    }
    override fun onResume() {
        MtpService.attach(activity)
    }

    @Command
    fun configure(invoke: Invoke) {
        try {
            val config = invoke.getArgs().getString("config") ?: error("config missing")
            val library = invoke.getArgs().optString("nativeLibrary").takeIf { it.isNotBlank() && it != "null" }
                ?: getConfig(MtpConfig::class.java)?.nativeLibrary
                ?: activity.getSharedPreferences("mtp-library", 0).getString("name", null)
                ?: error("Configure plugins.mtp.nativeLibrary with the host cdylib name")
            require(library.matches(Regex("[A-Za-z0-9_]+")))
            check(activity.getSharedPreferences("mtp-library", 0).edit().putString("name", library).commit())
            NativeBridge.load(activity)
            check(NativeBridge.start(config))
            SecureStore.save(activity, config)
            MtpService.attach(activity)
            invoke.resolve()
        } catch (error: Exception) { invoke.reject(error.message ?: "MTP configuration failed") }
    }

    @Command
    fun enable(invoke: Invoke) {
        try { MtpService.attach(activity); invoke.resolve() }
        catch (error: Exception) { invoke.reject(error.message ?: "MTP enable failed") }
    }

    @Command
    fun disable(invoke: Invoke) {
        try {
            SecureStore.setEnabled(activity, false)
            NativeBridge.stop()
            activity.stopService(android.content.Intent(activity, MtpService::class.java))
            invoke.resolve()
        } catch (error: Exception) { invoke.reject(error.message ?: "MTP disable failed") }
    }

    @Command
    fun clear(invoke: Invoke) {
        try {
            SecureStore.setEnabled(activity, false)
            NativeBridge.stop()
            activity.stopService(android.content.Intent(activity, MtpService::class.java))
            SecureStore.clear(activity)
            invoke.resolve()
        } catch (error: Exception) { invoke.reject(error.message ?: "MTP clear failed") }
    }
}
