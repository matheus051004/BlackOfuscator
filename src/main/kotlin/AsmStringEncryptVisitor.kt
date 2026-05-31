import com.android.build.api.instrumentation.AsmClassVisitorFactory
import com.android.build.api.instrumentation.ClassContext
import com.android.build.api.instrumentation.ClassData
import com.android.build.api.instrumentation.InstrumentationParameters
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.api.tasks.Input
import org.objectweb.asm.ClassVisitor
import org.objectweb.asm.Label
import org.objectweb.asm.MethodVisitor
import org.objectweb.asm.Opcodes
import java.util.Base64
import kotlin.random.Random

interface StringEncryptParams : InstrumentationParameters {
    @get:Input
    val key: Property<String>

    @get:Input
    val prefix: Property<String>

    @get:Input
    val packages: ListProperty<String>

    @get:Input
    val minLen: Property<Int>

    @get:Input
    val decryptorPackage: Property<String>

    @get:Input
    val decryptorClassNames: ListProperty<String>
}

abstract class AsmStringEncryptVisitorFactory :
    AsmClassVisitorFactory<StringEncryptParams> {

    override fun createClassVisitor(
        classContext: ClassContext,
        nextClassVisitor: ClassVisitor
    ): ClassVisitor {
        val key = parameters.get().key.get()
        val minLen = parameters.get().minLen.get()
        val decryptorPackage = parameters.get().decryptorPackage.get()
        val classNames = parameters.get().decryptorClassNames.get()
        val internalNames = classNames.map { "$decryptorPackage.$it".replace('.', '/') }
        return StringEncryptClassVisitor(nextClassVisitor, minLen, key, internalNames)
    }

    override fun isInstrumentable(classData: ClassData): Boolean {
        val decryptorPackage = parameters.get().decryptorPackage.get()
        val classNames = parameters.get().decryptorClassNames.get()

        // Skip all generated decryptor classes
        val decryptorFqcns = classNames.map { "$decryptorPackage.$it" }
        if (classData.className in decryptorFqcns) return false

        val packages = parameters.get().packages.get()
        if (packages.isNotEmpty()) {
            return packages.any { pkg -> classData.className.startsWith(pkg) }
        }

        val prefix = parameters.get().prefix.get().replace('/', '.')
        return classData.className.startsWith(prefix)
    }
}

/** Mutable counter shared across all methods in a class for consistent round-robin. */
private class Counter(var value: Int = 0)

private class StringEncryptClassVisitor(
    nextVisitor: ClassVisitor,
    private val minLen: Int,
    private val key: String,
    private val decryptorInternalNames: List<String>
) : ClassVisitor(Opcodes.ASM9, nextVisitor) {

    private val stringCounter = Counter(0)

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        return StringEncryptMethodVisitor(mv, minLen, key, decryptorInternalNames, stringCounter)
    }
}

private class StringEncryptMethodVisitor(
    nextVisitor: MethodVisitor,
    private val minLen: Int,
    private val key: String,
    private val decryptorInternalNames: List<String>,
    private val stringCounter: Counter
) : MethodVisitor(Opcodes.ASM9, nextVisitor) {

    // Buffered LDC string waiting to see if it's used as a loadLibrary/load argument.
    private var pendingString: String? = null

    /** Flush the buffered string — encrypt it and emit the decryptor call. */
    private fun flushPending() {
        val value = pendingString ?: return
        pendingString = null
        emitEncrypted(value)
    }

    /** Emit an encrypted string with its decryptor call. */
    private fun emitEncrypted(value: String) {
        val idx = stringCounter.value
        val salt = idx and 0xFF
        val encrypted = encrypt(value, salt)
        super.visitLdcInsn(encrypted)

        val targetClass = decryptorInternalNames[idx % decryptorInternalNames.size]
        mv.visitMethodInsn(
            Opcodes.INVOKESTATIC,
            targetClass,
            "decrypt",
            "(Ljava/lang/String;)Ljava/lang/String;",
            false
        )
        stringCounter.value++
    }

    companion object {
        private val NATIVE_LOAD_METHODS = setOf("loadLibrary", "load")
        private const val SYSTEM_INTERNAL = "java/lang/System"
        private val FRAMEWORK_SKIP = setOf(
            // Service names (Context.WINDOW_SERVICE, etc.)
            "window", "activity", "layout_inflater", "alarm", "notification",
            "accessibility", "account", "audio", "clipboard", "connectivity",
            "device_policy", "download", "input_method", "keyguard", "location",
            "nfc", "power", "search", "sensor", "storage", "telephony",
            "text_services", "ui_mode", "usb", "vibrator", "wallpaper", "wifi",
            "statusbar", "appwidget", "backup", "battery", "batterymanager",
            "camera", "job_scheduler", "consumer_ir", "cross_profile",
            "device_identifiers", "display", "print", "media_projection",
            "media_router", "media_session", "midi", "network_stats",
            "notification_policy", "restrictions", "shortcut", "stats",
            "usage_stats", "carrier_config",
            // Intent actions
            "android.intent.action.MAIN", "android.intent.action.VIEW",
            "android.intent.action.SEND", "android.intent.action.SENDTO",
            "android.intent.action.SEND_MULTIPLE", "android.intent.action.PICK",
            "android.intent.action.GET_CONTENT", "android.intent.action.INSERT",
            "android.intent.action.DELETE", "android.intent.action.EDIT",
            "android.intent.action.CALL", "android.intent.action.DIAL",
            "android.intent.action.ANSWER", "android.intent.action.BATTERY_LOW",
            "android.intent.action.BATTERY_OKAY", "android.intent.action.BOOT_COMPLETED",
            "android.intent.action.CAMERA_BUTTON", "android.intent.action.CONFIGURATION_CHANGED",
            "android.intent.action.DATE_CHANGED", "android.intent.action.DEVICE_STORAGE_LOW",
            "android.intent.action.DEVICE_STORAGE_OK", "android.intent.action.DOCK_EVENT",
            "android.intent.action.DREAMING_STARTED", "android.intent.action.DREAMING_STOPPED",
            "android.intent.action.EXTERNAL_APPLICATIONS_AVAILABLE",
            "android.intent.action.EXTERNAL_APPLICATIONS_UNAVAILABLE",
            "android.intent.action.HEADSET_PLUG", "android.intent.action.INPUT_METHOD_CHANGED",
            "android.intent.action.LOCALE_CHANGED", "android.intent.action.MANAGE_PACKAGE_STORAGE",
            "android.intent.action.MEDIA_BAD_REMOVAL", "android.intent.action.MEDIA_BUTTON",
            "android.intent.action.MEDIA_CHECKING", "android.intent.action.MEDIA_EJECT",
            "android.intent.action.MEDIA_MOUNTED", "android.intent.action.MEDIA_NOFS",
            "android.intent.action.MEDIA_REMOVED", "android.intent.action.MEDIA_SCANNER_FINISHED",
            "android.intent.action.MEDIA_SCANNER_SCAN_FILE", "android.intent.action.MEDIA_SCANNER_STARTED",
            "android.intent.action.MEDIA_SHARED", "android.intent.action.MEDIA_UNMOUNTABLE",
            "android.intent.action.MEDIA_UNMOUNTED", "android.intent.action.NEW_OUTGOING_CALL",
            "android.intent.action.PACKAGE_ADDED", "android.intent.action.PACKAGE_CHANGED",
            "android.intent.action.PACKAGE_DATA_CLEARED", "android.intent.action.PACKAGE_FIRST_LAUNCH",
            "android.intent.action.PACKAGE_FULLY_REMOVED", "android.intent.action.PACKAGE_INSTALL",
            "android.intent.action.PACKAGE_NEEDS_VERIFICATION",
            "android.intent.action.PACKAGE_REMOVED", "android.intent.action.PACKAGE_REPLACED",
            "android.intent.action.PACKAGE_RESTARTED", "android.intent.action.PACKAGE_VERIFIED",
            "android.intent.action.POWER_CONNECTED", "android.intent.action.POWER_DISCONNECTED",
            "android.intent.action.PROVIDER_CHANGED", "android.intent.action.REBOOT",
            "android.intent.action.SCREEN_OFF", "android.intent.action.SCREEN_ON",
            "android.intent.action.SHUTDOWN", "android.intent.action.TIMEZONE_CHANGED",
            "android.intent.action.TIME_CHANGED", "android.intent.action.TIME_TICK",
            "android.intent.action.UID_REMOVED", "android.intent.action.USER_PRESENT",
            "android.intent.action.WALLPAPER_CHANGED",
            "android.intent.action.INSTALL_PACKAGE", "android.intent.action.UNINSTALL_PACKAGE",
            "android.intent.action.SEARCH", "android.intent.action.WEB_SEARCH",
            "android.intent.action.AIRPLANE_MODE", "android.intent.action.APPLICATION_RESTRICTIONS_CHANGED",
            "android.intent.action.APP_ERROR", "android.intent.action.BUG_REPORT",
            "android.intent.action.PASTE", "android.intent.action.COPY",
            "android.intent.action.CUT", "android.intent.action.OPEN_DOCUMENT",
            "android.intent.action.OPEN_DOCUMENT_TREE", "android.intent.action.CREATE_DOCUMENT",
            "android.intent.action.PICK_ACTIVITY", "android.intent.action.CHOOSER",
            "android.intent.action.SETTINGS", "android.intent.action.APN_SETTINGS",
            "android.intent.action.INPUT_METHOD_SETTINGS",
            "android.intent.action.LOCALE_SETTINGS", "android.intent.action.SECURITY_SETTINGS",
            "android.intent.action.WIFI_SETTINGS", "android.intent.action.WIRELESS_SETTINGS",
            "android.intent.action.ACCESSIBILITY_SETTINGS", "android.intent.action.ADD_ACCOUNT",
            "android.intent.action.DATE_SETTINGS", "android.intent.action.DEVICE_INFO_SETTINGS",
            "android.intent.action.DISPLAY_SETTINGS", "android.intent.action.INTERNAL_STORAGE_SETTINGS",
            "android.intent.action.MEMORY_CARD_SETTINGS", "android.intent.action.NETWORK_OPERATOR_SETTINGS",
            "android.intent.action.NFCSHARING_SETTINGS", "android.intent.action.NFC_PAYMENT_SETTINGS",
            "android.intent.action.PRIVACY_SETTINGS", "android.intent.action.QUICK_CLOCK",
            "android.intent.action.QUICK_VIEW", "android.intent.action.SYNC_SETTINGS",
            "android.intent.action.SYSTEM_UPDATE_SETTINGS", "android.intent.action.USER_DICTIONARY_INSERT",
            "android.intent.action.USER_DICTIONARY_SETTINGS",
            "android.intent.action.VOICE_COMMAND", "android.intent.action.MANAGED_PROFILE_PROVISIONED",
            "android.intent.action.BATTERY_CHANGED",
            // Intent categories
            "android.intent.category.LAUNCHER", "android.intent.category.DEFAULT",
            "android.intent.category.BROWSABLE", "android.intent.category.HOME",
            "android.intent.category.PREFERENCE", "android.intent.category.ALTERNATIVE",
            "android.intent.category.SELECTED_ALTERNATIVE", "android.intent.category.TAB",
            "android.intent.category.EMBED", "android.intent.category.APP_MARKET",
            "android.intent.category.CAR_DOCK", "android.intent.category.CAR_MODE",
            "android.intent.category.DESK_DOCK", "android.intent.category.DESK_MODE",
            "android.intent.category.DEVELOPMENT_PREFERENCE", "android.intent.category.HE_DESK_DOCK",
            "android.intent.category.HE_DESK_MODE", "android.intent.category.INFO",
            "android.intent.category.MONKEY", "android.intent.category.NOTIFICATION_PREFERENCES",
            "android.intent.category.OPENABLE", "android.intent.category.SAMPLE_CODE",
            "android.intent.category.TEST", "android.intent.category.UNIT_TEST",
            "android.intent.category.VR_HOME", "android.intent.category.LEANBACK_LAUNCHER",
            // MIME types
            "text/plain", "text/html", "text/xml", "text/css", "text/csv",
            "application/json", "application/xml", "application/pdf",
            "application/octet-stream", "application/x-www-form-urlencoded",
            "application/zip", "application/gzip", "image/*", "image/jpeg",
            "image/png", "image/gif", "image/webp", "image/svg+xml",
            "video/*", "video/mp4", "video/webm", "audio/*", "audio/mpeg",
            "audio/ogg", "audio/wav", "multipart/form-data",
            // Android framework XML namespaces
            "http://schemas.android.com/apk/res/android",
            "http://schemas.android.com/apk/res-auto",
            "http://schemas.android.com/tools",
            // Common framework identifiers
            "utf-8", "UTF-8", "SHA-256", "SHA-1", "MD5", "AES", "RSA",
            "HmacSHA256", "HmacSHA1", "BC", "AndroidKeyStore",
            "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS",
            "Content-Type", "Authorization", "Accept", "User-Agent",
        )

        private val SIMPLE_SKIP = setOf(
            "true", "false", "null", "none", "auto", "wrap", "fill",
            "match_parent", "fill_parent", "visible", "invisible", "gone",
            "horizontal", "vertical", "center", "left", "right", "top", "bottom",
            "start", "end", "bold", "italic", "normal", "sans", "serif", "monospace",
            "always", "never", "ifRoom", "withText", "beginning", "middle", "marquee",
            "ltr", "rtl", "locale", "password", "number", "text", "email", "phone",
            "date", "time", "datetime", "send", "done", "go", "next",
            "unspecified", "behind", "fullscreen", "immersive", "leanback",
            "nosensor", "user", "system", "dark", "light",
            "no", "yes", "default", "standard", "sandbox", "production",
            "debug", "release", "profile", "direct", "indirect",
            "high", "medium", "low", "min", "max",
            "small", "normal", "large", "xlarge",
            "short", "long"
        )

        private fun shouldSkip(value: String): Boolean {
            if (FRAMEWORK_SKIP.contains(value)) return true
            // Skip common framework packages — never encrypt these
            if (value.startsWith("android.")) return true
            if (value.startsWith("java.") || value.startsWith("javax.")) return true
            if (value.startsWith("kotlin.") || value.startsWith("kotlinx.")) return true
            if (value.startsWith("org.") && (
                value.startsWith("org.json.") ||
                value.startsWith("org.xml.") ||
                value.startsWith("org.w3c.") ||
                value.startsWith("org.xmlpull.") ||
                value.startsWith("org.apache.")
            )) return true
            // Skip XML namespace URIs
            if (value.startsWith("http://schemas.android.com/")) return true
            // Skip resource references
            if (value.startsWith("@")) return true
            // Skip file extensions
            if (value.matches(Regex("^\\.[a-z0-9]{2,5}$"))) return true
            // Skip simple single-word lowercase identifiers
            if (value.matches(Regex("^[a-z][a-z0-9_]{0,30}$")) && SIMPLE_SKIP.contains(value)) return true
            return false
        }
    }

    override fun visitLdcInsn(value: Any?) {
        // Flush any previously buffered string before handling a new instruction
        flushPending()

        if (value is String && value.length >= minLen && !shouldSkip(value)) {
            // Buffer the string — we need to see if the next instruction is
            // System.loadLibrary()/load() before deciding to encrypt.
            pendingString = value
        } else {
            super.visitLdcInsn(value)
        }
    }

    override fun visitMethodInsn(
        opcode: Int,
        owner: String,
        name: String,
        descriptor: String,
        isInterface: Boolean
    ) {
        // Check if a buffered string is being passed to System.loadLibrary() or System.load()
        if (pendingString != null &&
            opcode == Opcodes.INVOKESTATIC &&
            owner == SYSTEM_INTERNAL &&
            name in NATIVE_LOAD_METHODS &&
            descriptor == "(Ljava/lang/String;)V"
        ) {
            // Emit the original unencrypted string — native lib names must not be encrypted
            val original = pendingString!!
            pendingString = null
            super.visitLdcInsn(original)
        } else {
            flushPending()
        }

        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
    }

    // Flush on any other bytecode instruction that could follow an LDC
    override fun visitInsn(opcode: Int) { flushPending(); super.visitInsn(opcode) }
    override fun visitIntInsn(opcode: Int, operand: Int) { flushPending(); super.visitIntInsn(opcode, operand) }
    override fun visitVarInsn(opcode: Int, `var`: Int) { flushPending(); super.visitVarInsn(opcode, `var`) }
    override fun visitTypeInsn(opcode: Int, type: String?) { flushPending(); super.visitTypeInsn(opcode, type) }
    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) { flushPending(); super.visitFieldInsn(opcode, owner, name, descriptor) }
    override fun visitJumpInsn(opcode: Int, label: Label?) { flushPending(); super.visitJumpInsn(opcode, label) }
    override fun visitLabel(label: Label) { flushPending(); super.visitLabel(label) }
    override fun visitIincInsn(`var`: Int, increment: Int) { flushPending(); super.visitIincInsn(`var`, increment) }
    override fun visitTableSwitchInsn(min: Int, max: Int, dflt: Label?, vararg labels: Label?) { flushPending(); super.visitTableSwitchInsn(min, max, dflt, *labels) }
    override fun visitLookupSwitchInsn(dflt: Label?, keys: IntArray?, labels: Array<out Label>?) { flushPending(); super.visitLookupSwitchInsn(dflt, keys, labels) }
    override fun visitMultiANewArrayInsn(descriptor: String?, numDimensions: Int) { flushPending(); super.visitMultiANewArrayInsn(descriptor, numDimensions) }

    /**
     * Encrypt with per-string salt:
     * - salt byte is prepended to the encrypted data
     * - check byte = salt ^ 0xA7 (integrity validation)
     * - key XOR is shifted by salt value
     * Result: Base64(salt + check + encrypted_bytes)
     */
    private fun encrypt(plain: String, salt: Int): String {
        val keyBytes = key.toByteArray(Charsets.UTF_8)
        val original = plain.toByteArray(Charsets.UTF_8)
        val encrypted = ByteArray(original.size + 2)

        // Prepend salt and check bytes
        encrypted[0] = salt.toByte()
        encrypted[1] = (salt xor 0xA7).toByte()

        for (i in original.indices) {
            var b = original[i].toInt() and 0xFF
            // XOR with salt-shifted key + position
            b = b xor (keyBytes[(i + salt) % keyBytes.size].toInt() xor ((i + salt) and 0xFF))
            // Rotate left 4 bits
            b = ((b shl 4) or (b ushr 4)) and 0xFF
            encrypted[i + 2] = b.toByte()
        }
        return Base64.getEncoder().encodeToString(encrypted)
    }
}
