package com.v2ray.ang.core

import android.content.Context
import com.v2ray.ang.AppConfig
import com.v2ray.ang.enums.CoreType
import com.v2ray.ang.util.LogUtil
import com.v2ray.ang.util.Utils
import go.Seq
import libv2ray.CoreCallbackHandler
import libv2ray.CoreController
import libv2ray.CoreOptions
import libv2ray.KitePlatform
import libv2ray.Libv2ray
import java.util.concurrent.atomic.AtomicBoolean

/**
 * V2Ray Native Library Manager
 *
 * Thread-safe singleton wrapper for Libv2ray native methods.
 * Provides initialization protection and unified API for V2Ray core operations.
 */
object CoreNativeManager {
    private val initialized = AtomicBoolean(false)

    /**
     * Initialize V2Ray core environment.
     * This method is thread-safe and ensures initialization happens only once.
     * Subsequent calls will be ignored silently.
     *
     */
    fun initCoreEnv(context: Context?) {
        if (initialized.compareAndSet(false, true)) {
            try {
                Seq.setContext(context?.applicationContext)
                val assetPath = Utils.userAssetPath(context)
                val deviceId = Utils.getDeviceIdForXUDPBaseKey()
                Libv2ray.initCoreEnv(assetPath, deviceId)
                LogUtil.i(AppConfig.TAG, "V2Ray core environment initialized successfully")
            } catch (e: Exception) {
                LogUtil.e(AppConfig.TAG, "Failed to initialize V2Ray core environment", e)
                initialized.set(false)
                throw e
            }
        } else {
            LogUtil.d(AppConfig.TAG, "V2Ray core environment already initialized, skipping")
        }
    }

    fun reconcileBrowserDialer(dialerAddr: String) {
        try {
            Libv2ray.reconcileBrowserDialer(dialerAddr)
            LogUtil.i(AppConfig.TAG, "Browser dialer reconciled successfully with address: $dialerAddr")
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to reconcile browser dialer with address: $dialerAddr", e)
        }
    }


    /**
     * Get V2Ray core version.
     *
     * @return Version string of the V2Ray core
     */
    fun getLibVersion(): String {
        return try {
            Libv2ray.checkVersionX()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to check V2Ray version", e)
            "Unknown"
        }
    }

    /**
     * Measure outbound connection delay.
     *
     * @param config The configuration JSON string
     * @param testUrl The URL to test against
     * @return Delay in milliseconds, or -1 if test failed
     */
    fun measureOutboundDelay(config: String, testUrl: String): Long {
        return try {
            Libv2ray.measureOutboundDelay(config, testUrl)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to measure outbound delay", e)
            -1L
        }
    }

    /**
     * Create a new core controller instance.
     *
     * @param handler The callback handler for core events
     * @return A new CoreController instance
     */
    fun newCoreController(handler: CoreCallbackHandler): CoreController {
        return try {
            Libv2ray.newCoreController(handler)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to create core controller", e)
            throw e
        }
    }

    // ---- mihomo / sing-box (libkite) ----

    /** Installs the Android callbacks every core uses (protect, process lookup, sing-box tun, logs). */
    fun registerKitePlatform(platform: KitePlatform?) {
        Libv2ray.registerKitePlatform(platform)
    }

    /** Starts mihomo or sing-box, stopping whichever of the two ran before. Throws on failure. */
    @Throws(Exception::class)
    fun startKiteCore(core: CoreType, content: String, options: CoreOptions) {
        require(core != CoreType.XRAY) { "Xray runs through CoreController" }
        Libv2ray.startKiteCore(core.value, content, options)
    }

    /** Stops mihomo or sing-box and releases their ports and descriptors. No-op when idle. */
    fun stopKiteCore() {
        try {
            Libv2ray.stopKiteCore()
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to stop mihomo/sing-box", e)
        }
    }

    fun isKiteCoreRunning(): Boolean = Libv2ray.isKiteCoreRunning()

    /** Delay through the running mihomo / sing-box in milliseconds, -1 on failure. */
    @Throws(Exception::class)
    fun measureKiteDelay(url: String, timeoutMs: Int): Long = Libv2ray.measureKiteDelay(url, timeoutMs)

    /** Offline delay test of a mihomo / sing-box configuration, -1 on failure. */
    fun measureKiteOutboundDelay(core: CoreType, content: String, url: String, timeoutMs: Int, homeDir: String): Long {
        return try {
            Libv2ray.measureKiteOutboundDelay(core.value, content, AppConfig.TAG_PROXY, url, timeoutMs, homeDir)
        } catch (e: Exception) {
            LogUtil.w(AppConfig.TAG, "Failed to measure ${core.value} delay: ${e.message}")
            -1L
        }
    }

    /** Traffic since the previous call, "tag,direction,value;" as Xray reports it. */
    fun queryKiteTrafficStats(): String = Libv2ray.queryKiteTrafficStats()

    fun getKiteGroups(): String = Libv2ray.getKiteGroups()

    @Throws(Exception::class)
    fun selectKiteOutbound(group: String, name: String) = Libv2ray.selectKiteOutbound(group, name)

    fun updateDefaultInterface(name: String, index: Int) = Libv2ray.updateDefaultInterface(name, index)

    fun updateSystemDns(servers: String) = Libv2ray.updateSystemDNS(servers)

    /** "mihomo", "sing-box", "xray" or "" for a full configuration (import detection). */
    fun detectCoreConfig(content: String): String {
        return try {
            Libv2ray.detectCoreConfig(content)
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to detect config core", e)
            ""
        }
    }

    /** Validates a native configuration for [core]; returns the error message or null. */
    fun checkCoreConfig(core: CoreType, content: String): String? {
        return try {
            Libv2ray.checkCoreConfig(core.value, content)
            null
        } catch (e: Exception) {
            e.message ?: e.javaClass.simpleName
        }
    }

    /** Versions of the three embedded cores for the About page. */
    fun getCoreVersions(): Map<CoreType, String> {
        return try {
            mapOf(
                CoreType.XRAY to getLibVersion(),
                CoreType.MIHOMO to Libv2ray.mihomoVersion(),
                CoreType.SING_BOX to Libv2ray.singBoxVersion(),
            )
        } catch (e: Exception) {
            LogUtil.e(AppConfig.TAG, "Failed to read core versions", e)
            emptyMap()
        }
    }
}
