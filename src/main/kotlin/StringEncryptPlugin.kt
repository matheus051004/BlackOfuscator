import com.android.build.api.instrumentation.FramesComputationMode
import com.android.build.api.instrumentation.InstrumentationScope
import com.android.build.api.variant.AndroidComponentsExtension
import org.gradle.api.DefaultTask
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.tasks.Input
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.TaskAction
import java.io.File
import java.util.Base64

/**
 * Generates N decryptor Java source files with a shuffled S-box permutation
 * and a per-class fixed XOR key derived from the master key + class index.
 *
 * Classes form a dependency chain: ~70% call helper methods on other classes
 * as part of the decryption logic, making isolated analysis much harder.
 */
class StringEncryptPlugin : Plugin<Project> {
    override fun apply(project: Project) {
        val extension = project.extensions.create("stringEncrypt", StringEncryptExtension::class.java)

        // Set sensible defaults
        extension.key.convention("DefaultEncryptKey2024")
        extension.minLen.convention(8)
        extension.decryptorPackage.convention("com.myapp.encrypted")
        extension.decryptorCount.convention(3)
        extension.prefix.convention("com/myapp")
        extension.packages.convention(emptyList())
        extension.controlFlowObfuscation.convention(true)
        extension.nativeLibName.convention("BlackOfuscator")

        val genTask = project.tasks.register("generateStringDecryptors", GenerateDecryptorsTask::class.java) { task ->
            task.key.set(extension.key)
            task.minLen.set(extension.minLen)
            task.decryptorPackage.set(extension.decryptorPackage)
            task.decryptorCount.set(extension.decryptorCount)
            task.nativeLibName.set(extension.nativeLibName)
        }

        project.afterEvaluate {
            project.tasks.configureEach { task ->
                if (task.name.matches(Regex("compile\\w+JavaWithJavac")) ||
                    task.name.matches(Regex("compile\\w+Kotlin"))) {
                    task.dependsOn(genTask)
                }
                // Ensure native_decrypt.c is generated before CMake configures
                if (task.name.startsWith("configureCMake") || task.name.startsWith("buildCMake") ||
                    task.name.contains("CMakeDebug") || task.name.contains("CMakeRel")) {
                    task.dependsOn(genTask)
                }
            }
        }

        // Register ASM transforms
        val androidComponents = project.extensions.findByType(AndroidComponentsExtension::class.java)
        androidComponents?.onVariants { variant ->
            val classNames = (0 until extension.decryptorCount.get()).map { generateClassName(it) }

            variant.instrumentation.transformClassesWith(
                AsmStringEncryptVisitorFactory::class.java,
                InstrumentationScope.ALL
            ) { params ->
                params.key.set(extension.key)
                params.minLen.set(extension.minLen)
                params.prefix.set(extension.prefix)
                params.packages.set(extension.packages)
                params.decryptorPackage.set(extension.decryptorPackage)
                params.decryptorClassNames.set(classNames)
            }

            variant.instrumentation.transformClassesWith(
                ControlFlowObfuscationVisitorFactory::class.java,
                InstrumentationScope.ALL
            ) { params ->
                params.enabled.set(extension.controlFlowObfuscation)
                params.prefix.set(extension.prefix)
                params.packages.set(extension.packages)
                params.decryptorPackage.set(extension.decryptorPackage)
                params.decryptorClassNames.set(classNames)
            }

            variant.instrumentation.setAsmFramesComputationMode(
                FramesComputationMode.COMPUTE_FRAMES_FOR_INSTRUMENTED_METHODS
            )
        }
    }

    private fun generateClassName(index: Int): String {
        val letters = "abcdefghijklmnopqrstuvwxyz"
        return if (index < 26) {
            "_d${letters[index]}"
        } else {
            "_d${letters[index / 26 - 1]}${letters[index % 26]}"
        }
    }
}

abstract class StringEncryptExtension {
    @get:Input
    abstract val key: org.gradle.api.provider.Property<String>

    @get:Input
    abstract val minLen: org.gradle.api.provider.Property<Int>

    @get:Input
    abstract val decryptorPackage: org.gradle.api.provider.Property<String>

    @get:Input
    abstract val decryptorCount: org.gradle.api.provider.Property<Int>

    @get:Input
    abstract val prefix: org.gradle.api.provider.Property<String>

    @get:Input
    abstract val packages: org.gradle.api.provider.ListProperty<String>

    @get:Input
    abstract val controlFlowObfuscation: org.gradle.api.provider.Property<Boolean>

    @get:Input
    abstract val nativeLibName: org.gradle.api.provider.Property<String>
}

abstract class GenerateDecryptorsTask : DefaultTask() {
    @get:Input
    abstract val key: org.gradle.api.provider.Property<String>

    @get:Input
    abstract val minLen: org.gradle.api.provider.Property<Int>

    @get:Input
    abstract val decryptorPackage: org.gradle.api.provider.Property<String>

    @get:Input
    abstract val decryptorCount: org.gradle.api.provider.Property<Int>

    @get:Input
    abstract val nativeLibName: org.gradle.api.provider.Property<String>

    @get:OutputDirectory
    val outputDir: DirectoryProperty = project.objects.directoryProperty()

    init {
        outputDir.set(project.layout.buildDirectory.dir("generated/stringDecryptors"))
    }

    @TaskAction
    fun generate() {
        val pkg = decryptorPackage.get()
        val count = decryptorCount.get()
        val key = key.get()
        val libName = nativeLibName.get()

        val classNames = (0 until count).map { generateClassName(it) }

        // Build dependency chain: shuffle classes deterministically,
        // then chain ~70% of them so each calls helper methods on another.
        val shuffled = shuffleDeterministic(classNames.toList(), key.hashCode())
        val chainSize = (shuffled.size * 7) / 10

        // depMap: className -> the class it depends on (null if standalone)
        val depMap = mutableMapOf<String, String?>()
        for (i in shuffled.indices) {
            if (i < chainSize - 1) {
                depMap[shuffled[i]] = shuffled[i + 1]
            } else {
                depMap[shuffled[i]] = null
            }
        }

        // Classes that are depended upon need _h/_m helper methods
        val dependedUpon = depMap.values.filterNotNull().toSet()

        val packagePath = pkg.replace('.', '/')
        val genDir = outputDir.dir(packagePath).get().asFile
        genDir.mkdirs()

        // Collect all keys for native embedding (one per decryptor)
        val keys = (0 until count).map { key }

        // Generate Java decryptors (delegate to native bridge)
        for ((index, className) in classNames.withIndex()) {
            val depClass = depMap[className]
            val needsHelpers = className in dependedUpon
            val outputFile = genDir.resolve("$className.java")
            outputFile.writeText(
                generateDecryptorSource(pkg, className, key, index, classNames, depClass, needsHelpers)
            )
            project.logger.lifecycle("  [string-encrypt] Generated decryptor: $pkg.$className" +
                if (depClass != null) " -> $depClass" else " (standalone)")
        }

        // Generate NativeBridge JNI class
        val bridgeFile = genDir.resolve("NativeBridge.java")
        bridgeFile.writeText(generateNativeBridgeSource(pkg, libName))
        project.logger.lifecycle("  [string-encrypt] Generated NativeBridge JNI class")

        // Generate native_decrypt.c into src/main/cpp/
        val cppDir = project.file("src/main/cpp")
        if (cppDir.isDirectory) {
            val nativeFile = cppDir.resolve("native_decrypt.c")
            nativeFile.writeText(generateNativeDecryptC(keys, pkg))
            project.logger.lifecycle("  [string-encrypt] Generated native_decrypt.c with ${keys.size} embedded keys")

            // Force CMake to reconfigure by deleting cached build files
            val cxxDir = project.layout.buildDirectory.dir(".cxx").get().asFile
            if (cxxDir.isDirectory) {
                cxxDir.listFiles()?.forEach { buildDir ->
                    buildDir.listFiles()?.forEach { cacheFile ->
                        if (cacheFile.name == "CMakeCache.txt" || cacheFile.name == "build.ninja") {
                            cacheFile.delete()
                            project.logger.lifecycle("  [string-encrypt] Deleted CMake cache: ${cacheFile.name}")
                        }
                    }
                }
            }
        } else {
            project.logger.warn("  [string-encrypt] src/main/cpp not found, skipping native_decrypt.c generation")
        }
    }

    /**
     * Deterministic Fisher-Yates shuffle using the seed as RNG.
     * Returns a new list with the same elements in shuffled order.
     */
    private fun shuffleDeterministic(list: List<String>, seed: Int): List<String> {
        val result = list.toMutableList()
        var s = seed
        for (i in result.size - 1 downTo 1) {
            s = s * 1103515245 + 12345
            val j = ((s ushr 16) and 0x7FFF) % (i + 1)
            val tmp = result[i]
            result[i] = result[j]
            result[j] = tmp
        }
        return result
    }

    private fun generateClassName(index: Int): String {
        val letters = "abcdefghijklmnopqrstuvwxyz"
        return if (index < 26) {
            "_d${letters[index]}"
        } else {
            "_d${letters[index / 26 - 1]}${letters[index % 26]}"
        }
    }

    private fun generateSbox(index: Int, key: String): IntArray {
        val base = IntArray(256) { it }
        var h = key.hashCode() xor (index * 0x5DEECE66D.toInt())
        for (i in 255 downTo 1) {
            h = h * 1103515245 + 12345
            val j = ((h ushr 16) and 0x7FFF) % (i + 1)
            val tmp = base[i]
            base[i] = base[j]
            base[j] = tmp
        }
        return base
    }

    /**
     * Generates a decryptor source that delegates to NativeBridge.d() (JNI).
     * The actual decryption runs in native code, making key extraction
     * significantly harder than from Java bytecode.
     *
     * Decoy fields (_s, _dep, _k, _h, _m) remain to confuse reverse engineers
     * but are NOT used by the decrypt path.
     */
    private fun generateDecryptorSource(
        pkg: String,
        className: String,
        key: String,
        index: Int,
        allClassNames: List<String>,
        depClassName: String?,
        needsHelpers: Boolean
    ): String {
        val sbox = generateSbox(index, key)
        val sboxLiteral = sbox.joinToString(", ")
        val depFqcn = if (depClassName != null) "$pkg.$depClassName" else null

        // _k: per-class constant used in _h/_m helpers (obfuscation decoys)
        val extraKey = (key.hashCode() xor (index * 0x1F3A5B7D)) and 0x7FFF

        // Helper methods — present on classes that are depended upon.
        // These look like they participate in decryption but are obfuscation decoys.
        val helperMethods = if (needsHelpers) {
            """
    static int _h(int _v, int _i) {
        _v ^= _s[(_i + _v) & 0xFF];
        _v = ((_v << 5) | (_v >>> 3));
        return (_v ^ _k) & 0xFFFF;
    }

    static int _m(int _v) {
        return _s[_v & 0xFF] ^ _k;
    }"""
        } else ""
        val depField = if (depFqcn != null) "\n    static $depFqcn _dep;" else ""
        val kField = if (needsHelpers) "\n    static int _k = 0x${extraKey.toString(16)};" else ""

        return """package $pkg;

public class $className {
    static int[] _s = {$sboxLiteral};$depField$kField
$helperMethods
    public static String decrypt(String s) {
        return $pkg.NativeBridge.d($index, s);
    }
}
"""
    }

    /**
     * Generates the NativeBridge JNI class that loads the native decrypt library
     * and exposes the native decrypt method.
     */
    private fun generateNativeBridgeSource(pkg: String, libName: String): String {
        return """package $pkg;

public class NativeBridge {
    static { System.loadLibrary("$libName"); }
    public static native String d(int idx, String s);
}
"""
    }

    /**
     * Generates native_decrypt.c — a JNI implementation with embedded key arrays.
     * Key bytes are stored as XOR-obfuscated arrays with a per-key mask.
     */
    private fun generateNativeDecryptC(keys: List<String>, pkg: String): String {
        val sb = StringBuilder()
        sb.appendLine("#include <jni.h>")
        sb.appendLine("#include <string.h>")
        sb.appendLine("#include <stdlib.h>")
        sb.appendLine()
        sb.appendLine("static const unsigned char b64d[256] = {")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,62,64,64,64,63,")
        sb.appendLine("    52,53,54,55,56,57,58,59,60,61,64,64,64,64,64,64,")
        sb.appendLine("    64, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,")
        sb.appendLine("    15,16,17,18,19,20,21,22,23,24,25,64,64,64,64,64,")
        sb.appendLine("    64,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,")
        sb.appendLine("    41,42,43,44,45,46,47,48,49,50,51,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,")
        sb.appendLine("    64,64,64,64,64,64,64,64,64,64,64,64,64,64,64,64")
        sb.appendLine("};")
        sb.appendLine()

        // Generate obfuscated key arrays
        for ((i, key) in keys.withIndex()) {
            val keyBytes = key.toByteArray(Charsets.UTF_8)
            val mask = (key.hashCode() xor (i * 0x9E3779B9.toInt())) and 0xFF
            val obfuscated = keyBytes.joinToString(",") {
                "0x${((it.toInt() and 0xFF) xor mask).toString(16).padStart(2, '0')}"
            }
            sb.appendLine("static const unsigned char _k${i}[] = {$obfuscated};")
            sb.appendLine("static const int _m${i} = 0x${mask.toString(16).padStart(2, '0')};")
            sb.appendLine("static const int _l${i} = ${keyBytes.size};")
        }
        sb.appendLine()

        // JNI decrypt function
        val jniPkg = pkg.replace('.', '_')
        sb.appendLine("JNIEXPORT jstring JNICALL")
        sb.appendLine("Java_${jniPkg}_NativeBridge_d(JNIEnv *env, jclass cls, jint idx, jstring js) {")
        sb.appendLine("    const char *s = (*env)->GetStringUTFChars(env, js, 0);")
        sb.appendLine("    int sl = (int)strlen(s);")
        sb.appendLine("    int ol = sl * 3 / 4 + 1;")
        sb.appendLine("    unsigned char *out = (unsigned char *)malloc(ol);")
        sb.appendLine("    int oi = 0;")
        sb.appendLine("    for (int i = 0; i < sl;) {")
        sb.appendLine("        unsigned char a = i < sl ? b64d[(unsigned char)s[i++]] : 64;")
        sb.appendLine("        unsigned char b = i < sl ? b64d[(unsigned char)s[i++]] : 64;")
        sb.appendLine("        unsigned char c = i < sl ? b64d[(unsigned char)s[i++]] : 64;")
        sb.appendLine("        unsigned char d = i < sl ? b64d[(unsigned char)s[i++]] : 64;")
        sb.appendLine("        if (a > 63 || b > 63) break;")
        sb.appendLine("        out[oi++] = (a << 2) | (b >> 4);")
        sb.appendLine("        if (c > 63) break;")
        sb.appendLine("        out[oi++] = (b << 4) | (c >> 2);")
        sb.appendLine("        if (d > 63) break;")
        sb.appendLine("        out[oi++] = (c << 6) | d;")
        sb.appendLine("    }")
        sb.appendLine("    (*env)->ReleaseStringUTFChars(env, js, s);")
        sb.appendLine("    if (oi < 2) { free(out); return js; }")
        sb.appendLine()

        // Select key array by index using switch
        sb.appendLine("    const unsigned char *kb; int mask, kblen;")
        sb.appendLine("    switch(idx) {")
        for (i in keys.indices) {
            sb.appendLine("        case $i: kb=_k${i}; mask=_m${i}; kblen=_l${i}; break;")
        }
        sb.appendLine("        default: free(out); return js;")
        sb.appendLine("    }")
        sb.appendLine()

        // Decrypt
        sb.appendLine("    int sa = out[0];")
        sb.appendLine("    int cb = out[1];")
        sb.appendLine("    if ((sa ^ 0xA7) != cb) { free(out); return js; }")
        sb.appendLine("    int rl = oi - 2;")
        sb.appendLine("    unsigned char *r = (unsigned char *)malloc(rl + 1);")
        sb.appendLine("    for (int i = 0; i < rl; i++) {")
        sb.appendLine("        int v = out[i + 2];")
        sb.appendLine("        v = ((v >> 4) | (v << 4)) & 0xFF;")
        sb.appendLine("        v ^= ((kb[(i + sa) % kblen] ^ mask) & 0xFF) ^ ((i + sa) & 0xFF);")
        sb.appendLine("        r[i] = (unsigned char)v;")
        sb.appendLine("    }")
        sb.appendLine("    r[rl] = 0;")
        sb.appendLine("    free(out);")
        sb.appendLine("    jstring result = (*env)->NewStringUTF(env, (const char *)r);")
        sb.appendLine("    free(r);")
        sb.appendLine("    return result;")
        sb.appendLine("}")

        return sb.toString()
    }
}
