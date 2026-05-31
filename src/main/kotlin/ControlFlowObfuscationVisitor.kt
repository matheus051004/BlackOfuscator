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
import kotlin.random.Random

interface ControlFlowObfuscationParams : InstrumentationParameters {
    @get:Input
    val enabled: Property<Boolean>

    @get:Input
    val prefix: Property<String>

    @get:Input
    val packages: ListProperty<String>

    @get:Input
    val decryptorPackage: Property<String>

    @get:Input
    val decryptorClassNames: ListProperty<String>
}

abstract class ControlFlowObfuscationVisitorFactory :
    AsmClassVisitorFactory<ControlFlowObfuscationParams> {

    override fun createClassVisitor(
        classContext: ClassContext,
        nextClassVisitor: ClassVisitor
    ): ClassVisitor {
        val enabled = parameters.get().enabled.get()
        val seed = classContext.currentClassData.className.hashCode()
        return ControlFlowClassVisitor(nextClassVisitor, enabled, seed)
    }

    override fun isInstrumentable(classData: ClassData): Boolean {
        val enabled = parameters.get().enabled.get()
        if (!enabled) return false

        val decryptorPackage = parameters.get().decryptorPackage.get()
        val classNames = parameters.get().decryptorClassNames.get()
        if (classData.className in classNames.map { "$decryptorPackage.$it" }) return false

        val simpleName = classData.className.substringAfterLast('.')
        if (simpleName == "R" || simpleName.startsWith("R\$") ||
            simpleName == "BuildConfig" || simpleName == "Manifest") return false

        val packages = parameters.get().packages.get()
        if (packages.isNotEmpty()) {
            return packages.any { pkg -> classData.className.startsWith(pkg) }
        }

        val prefix = parameters.get().prefix.get().replace('/', '.')
        return classData.className.startsWith(prefix)
    }
}

private class ControlFlowClassVisitor(
    nextVisitor: ClassVisitor,
    private val enabled: Boolean,
    private val seed: Int
) : ClassVisitor(Opcodes.ASM9, nextVisitor) {

    override fun visitMethod(
        access: Int,
        name: String,
        descriptor: String,
        signature: String?,
        exceptions: Array<out String>?
    ): MethodVisitor {
        val mv = super.visitMethod(access, name, descriptor, signature, exceptions)
        if (!enabled || (access and (Opcodes.ACC_ABSTRACT or Opcodes.ACC_NATIVE)) != 0) {
            return mv
        }
        return ControlFlowMethodVisitor(mv, seed xor name.hashCode())
    }
}

/**
 * Inserts opaque predicates before method calls and field access.
 *
 * Pattern:
 *   PUSH <non-zero constant>     // always truthy
 *   IFNE real_code               // always taken
 *   GOTO real_code               // dead path — decompiler renders both branches
 *   real_code:
 *   <original instruction>
 *
 * Both branches jump to the same target — no stack corruption, no dead code to validate.
 * Decompilers must render the if/else structure, making output significantly harder to read.
 */
private class ControlFlowMethodVisitor(
    nextVisitor: MethodVisitor,
    seed: Int
) : MethodVisitor(Opcodes.ASM9, nextVisitor) {

    private val rng = Random(seed)
    private var injectionCount = 0

    private fun insertOpaquePredicate() {
        injectionCount++

        // Generate a constant that looks meaningful but is always non-zero
        val constValue = (rng.nextInt(0xFFFF) or 1)

        // Push the constant
        when {
            constValue <= 5 -> mv.visitInsn(Opcodes.ICONST_0 + constValue)
            constValue <= 127 -> mv.visitIntInsn(Opcodes.BIPUSH, constValue)
            constValue <= 32767 -> mv.visitIntInsn(Opcodes.SIPUSH, constValue)
            else -> mv.visitLdcInsn(constValue)
        }

        // Both branches jump to the same target — no dead code, no stack issues
        val target = Label()
        mv.visitJumpInsn(Opcodes.IFNE, target)
        // Dead path: GOTO same target (decompiler renders this as else branch)
        mv.visitJumpInsn(Opcodes.GOTO, target)
        mv.visitLabel(target)
    }

    // --- Injection before method calls (except constructors) ---

    override fun visitMethodInsn(
        opcode: Int,
        owner: String,
        name: String,
        descriptor: String,
        isInterface: Boolean
    ) {
        if (name != "<init>" && name != "<clinit>") {
            insertOpaquePredicate()
        }
        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface)
    }

    // --- Injection before sensitive field access ---

    override fun visitFieldInsn(opcode: Int, owner: String, name: String, descriptor: String) {
        if (name.contains("url", ignoreCase = true) ||
            name.contains("token", ignoreCase = true) ||
            name.contains("key", ignoreCase = true) ||
            name.contains("secret", ignoreCase = true) ||
            name.contains("password", ignoreCase = true) ||
            name.contains("api", ignoreCase = true)) {
            insertOpaquePredicate()
        }
        super.visitFieldInsn(opcode, owner, name, descriptor)
    }
}
