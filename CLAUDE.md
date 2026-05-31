# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

BlackOfuscator is an Android Gradle plugin that encrypts string literals at compile time via ASM bytecode transformation, with JNI-based native decryption at runtime. It also injects opaque predicates for control flow obfuscation. Distributed via JitPack or local build-logic.

## Build commands

```bash
# Compile the plugin
./gradlew build

# Publish to local Maven repo (for testing consumers)
./gradlew publishToMavenLocal

# Clean
./gradlew clean
```

There are no tests — the project has no `src/test/` directory.

## Architecture

The plugin has three source files in `src/main/kotlin/` (no package — top-level classes):

### StringEncryptPlugin.kt — Plugin entry point

- Implements `Plugin<Project>`, registers the `stringEncrypt` extension (`StringEncryptExtension`) and the `generateStringDecryptors` task (`GenerateDecryptorsTask`).
- Registers two AGP ASM transforms via `AndroidComponentsExtension.onVariants{}`: `AsmStringEncryptVisitorFactory` and `ControlFlowObfuscationVisitorFactory`.
- The task generates: N decryptor Java classes (`_da`, `_db`, ...), a `NativeBridge.java` JNI bridge, and a `native_decrypt.c` file into `src/main/cpp/`.
- Decryptor class names use base-26 with `_d` prefix. ~70% form a dependency chain via `_dep` field (deterministic Fisher-Yates shuffle seeded by `key.hashCode()`).
- Task is wired as dependency of `compile*JavaWithJavac`, `compile*Kotlin`, and CMake tasks via `project.afterEvaluate`.
- After generating the C file, deletes CMake cache (`CMakeCache.txt`, `build.ninja`) in `build/.cxx/` to force reconfiguration.

### AsmStringEncryptVisitor.kt — String encryption transform

- `AsmStringEncryptVisitorFactory` → `StringEncryptClassVisitor` → `StringEncryptMethodVisitor`.
- Uses a `pendingString` buffer: `visitLdcInsn` buffers strings, other visitor methods flush via `flushPending()`. Special case: strings passed to `System.loadLibrary()`/`System.load()` are never encrypted (native lib names must remain plaintext).
- Encryption: salt byte prepended, check byte = `salt XOR 0xA7`, each byte XORed with `keyBytes[(i+salt) % keyLen] XOR ((i+salt) & 0xFF)`, then nibble-rotate, then Base64.
- `shouldSkip()` has ~300+ skip patterns: framework identifiers, XML namespaces, resource references, package prefixes, file extensions.
- Round-robin distribution across decryptor classes via shared `Counter`.

### ControlFlowObfuscationVisitor.kt — Opaque predicate injection

- Injects always-true predicates (`PUSH nonzero; IFNE target; GOTO target`) before method calls and sensitive field accesses (`url`, `token`, `key`, `secret`, `password`, `api`).
- Deterministic per-method RNG seeded by `className.hashCode() xor methodName.hashCode()`.
- Skips `R`, `R$*`, `BuildConfig`, `Manifest`, abstract, and native methods.

## Extension properties

All in `StringEncryptExtension` (registered as `stringEncrypt`):

| Property | Type | Default | Purpose |
|---|---|---|---|
| `key` | String | `"DefaultEncryptKey2024"` | XOR encryption key |
| `minLen` | Int | `8` | Min string length to encrypt |
| `decryptorPackage` | String | `"com.myapp.encrypted"` | Java package for generated decryptors |
| `decryptorCount` | Int | `3` | Number of decryptor classes |
| `prefix` | String | `"com/myapp"` | Class path prefix for transform scope |
| `packages` | List | `[]` | Explicit packages to process (overrides prefix) |
| `controlFlowObfuscation` | Boolean | `true` | Enable/disable opaque predicates |
| `nativeLibName` | String | `"BlackOfuscator"` | `System.loadLibrary()` name for JNI bridge |

## Build system

- Gradle 8.11.1, Kotlin 2.3.0, ASM 9.7.1
- AGP 9.2.1 is `compileOnly` — consuming Android project supplies its own AGP at runtime
- `java-gradle-plugin` auto-generates plugin metadata from `gradlePlugin {}` DSL (no `META-INF/gradle-plugins/` needed)
- `maven-publish` enables JitPack and `publishToMavenLocal`
- Plugin ID: `string-encrypt`, implementation class: `StringEncryptPlugin` (top-level)

## Distribution

- **JitPack**: consumers add `maven("https://jitpack.io")` and `classpath("com.github.matheus051004:BlackOfuscator:<version>")`
- **Local build-logic**: `includeBuild("build-logic")` with a composite build containing the plugin source
- `jitpack.yml` specifies `openjdk17` for JitPack builds

## JNI function name

The native decrypt function is `Java_<package>_NativeBridge_d` where `<package>` is `decryptorPackage` with dots replaced by underscores. E.g., `decryptorPackage = "com.th.lisoprime"` → `Java_com_th_lisoprime_NativeBridge_d`.

## Key gotchas

- The C decrypt must XOR key bytes with the mask during deobfuscation: `keyBytes[i] ^ mask`. Missing this causes JNI `illegal start byte` crashes.
- When using `apply(plugin = "string-encrypt")` (JitPack), the extension must be accessed via `configure<StringEncryptExtension> { ... }` — the `stringEncrypt { ... }` DSL accessor only works with `plugins { id("string-encrypt") }`.
- `native_decrypt.c` is generated into `src/main/cpp/` — the consuming project must have a `CMakeLists.txt` that compiles it and must register `src/main/cpp` as a CMake source set.
- ProGuard/R8 rules must keep the decryptor classes and `NativeBridge` with `@Keep` annotations or explicit `-keep` rules.
- The `packages` list, when non-empty, overrides `prefix` for transform scoping.
