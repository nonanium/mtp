package org.methanium.mtp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.os.Process
import android.os.SystemClock

class MtpService : Service() {
    private var started = false
    override fun onBind(intent: Intent?): IBinder? = null
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "org.methanium.mtp.STOP") {
            SecureStore.setEnabled(this, false)
            runCatching { NativeBridge.load(this); NativeBridge.stop() }
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        if (!SecureStore.enabled(this)) { stopSelf(); return START_NOT_STICKY }
        if (started) return START_STICKY
        val notifications = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= 26) notifications.createNotificationChannel(
            NotificationChannel("mtp", "Background connection", NotificationManager.IMPORTANCE_LOW))
        val stop = PendingIntent.getService(this, 1, Intent(this, MtpService::class.java)
            .setAction("org.methanium.mtp.STOP"), PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val builder = if (Build.VERSION.SDK_INT >= 26) Notification.Builder(this, "mtp") else Notification.Builder(this)
        builder.setContentTitle(applicationInfo.loadLabel(packageManager))
            .setContentText("Background connection active")
            .setSmallIcon(android.R.drawable.stat_notify_sync).setOngoing(true)
            .addAction(Notification.Action.Builder(null, "Stop", stop).build())
        packageManager.getLaunchIntentForPackage(packageName)?.let {
            builder.setContentIntent(PendingIntent.getActivity(this, 0, it, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT))
        }
        startForeground(19784, builder.build())
        val config = runCatching { SecureStore.load(this) }.getOrNull()
        if (config == null) { stopForeground(STOP_FOREGROUND_REMOVE); stopSelf(); return START_NOT_STICKY }
        try {
            NativeBridge.load(this)
            started = NativeBridge.start(config)
        } catch (error: Exception) {
            android.util.Log.e("MtpService", "Native startup failed", error)
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }
        return START_STICKY
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        val preferences = getSharedPreferences("mtp-lifecycle", MODE_PRIVATE)
        val now = SystemClock.elapsedRealtime()
        val last = preferences.getLong("taskRestart", 0)
        if (SecureStore.enabled(this) && (now < last || now - last >= 15_000)) {
            check(preferences.edit().putLong("taskRestart", now).commit())
            startService(Intent(this, MtpService::class.java))
            Process.killProcess(Process.myPid())
        }
        super.onTaskRemoved(rootIntent)
    }

    companion object {
        fun attach(context: Context) {
            if (runCatching { SecureStore.load(context) }.getOrNull() == null) return
            SecureStore.setEnabled(context, true)
            val intent = Intent(context, MtpService::class.java)
            if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(intent) else context.startService(intent)
        }
    }
}

class MtpBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED && SecureStore.enabled(context)) {
            runCatching {
                val service = Intent(context, MtpService::class.java)
                if (Build.VERSION.SDK_INT >= 26) context.startForegroundService(service) else context.startService(service)
            }
        }
    }
}

internal object NativeBridge {
    @Synchronized fun load(context: Context) {
        val library = context.getSharedPreferences("mtp-library", 0).getString("name", null)
            ?: error("MTP native library is not configured")
        require(library.matches(Regex("[A-Za-z0-9_]+")))
        System.loadLibrary(library)
    }
    @JvmStatic external fun start(config: String): Boolean
    @JvmStatic external fun stop()
}
