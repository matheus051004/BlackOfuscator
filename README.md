# BlackOfuscator

Gradle plugin for Android that automatically encrypts string literals in compiled bytecode using ASM class transformation. Strings are encrypted at build time and decrypted at runtime via JNI native code, no source code modification needed.

> **⚠️ Nenhuma ofuscagem é 100% segura.** Dedicando tempo e recursos suficientes, qualquer proteção pode ser revertida. O BlackOfuscator não é uma solução definitiva — é uma **camada extra de segurança** que aumenta significativamente o custo e o esforço necessários para extrair informações sensíveis do seu app. Pense nisso como um cadeado: não impede quem tem a chave certa, mas desencoraja a maioria dos invasores.
>
> **No obfuscation is 100% bulletproof.** Given enough time and resources, any protection can be reversed. BlackOfuscator is not a silver bullet — it's an **additional security layer** that raises the bar for extracting sensitive information from your app. Think of it as a lock: it won't stop someone with the right key, but it deters most attackers.

## How it works

1. During the build, the plugin scans all project classes matching the configured package filter
2. Every string literal (`LDC` instruction) longer than `minLen` is replaced with an encrypted value + a call to a runtime decryptor
3. Multiple decryptor classes with obfuscated names are auto-generated into `build/generated/stringDecryptors/`
4. A `NativeBridge.java` JNI bridge class is generated that loads the native decryption library
5. A `native_decrypt.c` file is generated with embedded XOR-obfuscated keys and compiled into a native `.so` via CMake
6. The decryptors form a **dependency chain**, each class calls helper methods on other classes, making isolated analysis much harder
7. Framework constants (Android services, Intent actions, MIME types, etc.) are automatically skipped
8. Each encrypted string includes a per-instance salt, so identical plaintexts produce different ciphertexts

## Encryption

Each string goes through multiple transformations before encoding:

1. **Per-string salt**, a random salt byte is generated per string at build time and prepended to the encrypted data. This ensures the same string encrypted in two different locations produces different output.
2. **XOR with salt-shifted key + position**, each byte is XORed with `key[(i + salt) % keyLen] XOR ((i + salt) & 0xFF)`, combining the encryption key, the per-string salt, and the byte position.
3. **Bit rotation**, each byte is rotated 4 bits (swapping high and low nibbles).
4. **Integrity check**, a check byte (`salt XOR 0xA7`) is included to validate the salt at decryption time.

The encrypted bytes are then Base64-encoded and stored as string constants in the DEX bytecode.

## Setup

There are two ways to install the plugin: **directly from GitHub** (via JitPack) or as a **local build-logic module**.

### Option A: Install from GitHub (JitPack)

This is the simplest approach — no need to copy any files into your project.

#### A1. Add JitPack repository

```kotlin
// settings.gradle.kts (project root)
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }  // add this
    }
}
```

#### A2. Add the plugin dependency

```kotlin
// build.gradle.kts (project root)
buildscript {
    repositories {
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
    dependencies {
        classpath("com.github.matheus051004:BlackOfuscator:main-SNAPSHOT")
    }
}
```

#### A3. Apply and configure the plugin in your app

```kotlin
// app/build.gradle.kts
plugins {
    alias(libs.plugins.android.application)
}

apply(plugin = "string-encrypt")

configure<StringEncryptExtension> {
    key.set("my-secret-key")
    decryptorPackage.set("com.myapp.encrypted")
    // ... other options
}
```

> **Note:** When using JitPack, use `apply(plugin = "string-encrypt")` + `configure<...>` instead of `id("string-encrypt")` + `stringEncrypt { ... }`. The latter only works with composite builds.

> **Tip:** Replace `main-SNAPSHOT` with a specific commit hash or tag for reproducible builds, e.g.:
> `classpath("com.github.matheus051004:BlackOfuscator:45c727e")`

### Option B: Local build-logic module

Use this if you want to customize the plugin source or avoid the JitPack dependency.

#### B1. Copy the plugin

Copy the `src/` and `build.gradle.kts` into your project:

```
your-project/
├── build-logic/
│   ├── settings.gradle.kts      # include(":string-encrypt")
│   └── string-encrypt/
│       ├── build.gradle.kts
│       ├── settings.gradle.kts
│       └── src/main/kotlin/
│           ├── StringEncryptPlugin.kt
│           ├── AsmStringEncryptVisitor.kt
│           └── ControlFlowObfuscationVisitor.kt
├── app/
└── settings.gradle.kts          # includeBuild("build-logic")
```

#### B2. Register the composite build

```kotlin
// settings.gradle.kts (project root)
pluginManagement {
    includeBuild("build-logic")
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
```

#### B3. Apply the plugin

```kotlin
// app/build.gradle.kts
plugins {
    alias(libs.plugins.android.application)
    id("string-encrypt")
}
```

### 2. Register generated source directory

The decryptor classes are generated into `build/generated/stringDecryptors/`. Register this directory as a source set so the compiler picks them up:

```kotlin
// app/build.gradle.kts
android {
    // ... your existing config ...

    @Suppress("UnstableApiUsage")
    sourceSets {
        getByName("main") {
            java.srcDir(layout.buildDirectory.dir("generated/stringDecryptors").get().asFile)
        }
    }
}
```

### 3. Set up the native library (CMake)

The decryption runs in native code via JNI. You need a `CMakeLists.txt` in `app/src/main/cpp/` that includes the auto-generated `native_decrypt.c`:

```cmake
# app/src/main/cpp/CMakeLists.txt
cmake_minimum_required(VERSION 3.22.1)

project(BlackOfuscator C)

add_library(
    BlackOfuscator
    SHARED
    native_decrypt.c
)
```

The plugin generates `native_decrypt.c` into `src/main/cpp/` on every build. Make sure this directory exists:

```bash
mkdir -p app/src/main/cpp
```

**Already have native code?** You can add `native_decrypt.c` to an existing library instead of creating a dedicated one. Just include it alongside your other sources:

```cmake
# You already have this, just add native_decrypt.c to it
add_library(
    mylib
    SHARED
    my_code.c
    other_code.c
    native_decrypt.c    # <-- add this line
)
```

Then set `nativeLibName.set("mylib")` in your plugin config. The `NativeBridge` will load `mylib` and find the decrypt function there.

```bash
mkdir -p app/src/main/cpp
```

And configure CMake in your `app/build.gradle.kts`:

```kotlin
android {
    // ...
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
        }
    }
}
```

> **Important:** The native library name in `CMakeLists.txt` must match the `nativeLibName` configured in the plugin (default: `"BlackOfuscator"`).

### 4. Configure

```kotlin
stringEncrypt {
    // Encryption key (required)
    key.set("my-secret-key")

    // Minimum string length to encrypt (default: 8)
    // Strings shorter than this are left as plaintext
    minLen.set(8)

    // Package for the auto-generated decryptor classes (default: "com.myapp.encrypted")
    // Classes are generated with obfuscated names (e.g., _da, _db, _dc)
    decryptorPackage.set("com.myapp.encrypted")

    // Number of decryptor classes to generate (default: 3)
    // Strings are distributed across all classes; more classes = harder to reverse
    decryptorCount.set(10)

    // Name of the native shared library (default: "BlackOfuscator")
    // Must match the library name in your CMakeLists.txt
    nativeLibName.set("BlackOfuscator")

    // Broad package prefix filter (default: "com/myapp")
    // Only classes under this prefix are processed (use slash notation)
    prefix.set("com/myapp")

    // Optional: granular package list (overrides prefix when set)
    // Use dot notation
    packages.set(listOf(
        "com.myapp.network",
        "com.myapp.utils",
        "com.myapp.auth"
    ))

    // Enable control flow obfuscation (default: true)
    // Injects opaque predicates before method calls and sensitive field access
    controlFlowObfuscation.set(true)
}
```

### 5. Add ProGuard rule

If you use R8 minification, add a keep rule to `proguard-rules.pro`:

```proguard
# String encryption decryptors, auto-generated obfuscated classes
# Keep entire class hierarchy (fields + methods) because R8 cannot see ASM-injected calls
-keep class com.myapp.encrypted._d** { *; }
```

Replace `com.myapp.encrypted` with your configured `decryptorPackage`.

### 6. Build

```bash
./gradlew assembleDebug    # encrypted strings in debug
./gradlew assembleRelease  # encrypted strings in release
```

## Configuration reference

| Property | Type | Default | Description |
|---|---|---|---|
| `key` | `String` | `"DefaultEncryptKey2024"` | Encryption key. Changing this requires a clean rebuild. |
| `minLen` | `Int` | `8` | Strings shorter than this are skipped. Set to `6` to encrypt more strings. |
| `decryptorPackage` | `String` | `"com.myapp.encrypted"` | Package for the auto-generated decryptor classes. |
| `decryptorCount` | `Int` | `3` | Number of decryptor classes to generate. Strings are distributed round-robin. |
| `nativeLibName` | `String` | `"BlackOfuscator"` | Name of the native `.so` library. Must match your `CMakeLists.txt`. |
| `prefix` | `String` | `"com/myapp"` | Broad filter, all project classes under this prefix are candidates. Use slash notation. |
| `packages` | `List<String>` | `[]` (empty) | When set, overrides `prefix`. Only classes in these packages are encrypted. Use dot notation. |
| `controlFlowObfuscation` | `Boolean` | `true` | Inject opaque predicates before method calls and sensitive field access. |

## Auto-generated output

The plugin generates the following files on every build (safe to delete, regenerated automatically):

### Java classes (`build/generated/stringDecryptors/<package>/`)

- **`NativeBridge.java`**, JNI bridge class that loads the native library and exposes `d(int idx, String s)` for decryption
- **`_da.java`, `_db.java`, ...**, Decryptor classes with obfuscated names. Each delegates to `NativeBridge.d()`. Contains decoy fields (`_s`, `_dep`, `_k`) and methods (`_h`, `_m`) that look like they participate in decryption but are obfuscation decoys

### Native code (`src/main/cpp/`)

- **`native_decrypt.c`**, JNI C implementation with embedded XOR-obfuscated key arrays. Contains the `Java_<package>_NativeBridge_d` function that Base64-decodes, validates integrity, and decrypts the string. Compiled into the native `.so` via CMake.

### Dependency chain

The decryptor classes form a dependency chain where ~70% of classes reference other classes via helper methods. This means an attacker cannot understand the decryption logic by analyzing a single class, they must trace the full chain across multiple classes, each with its own unique S-box permutation and mixing key.

Example chain: `_da → _do → _dz → _dn → _de → ...`

## What gets skipped automatically

The plugin maintains an internal skip list of ~300+ strings that should never be encrypted:

- **Android service names**, `"window"`, `"activity"`, `"connectivity"`, etc.
- **Intent actions**, `"android.intent.action.MAIN"`, `"android.intent.action.VIEW"`, etc.
- **Intent categories**, `"android.intent.category.LAUNCHER"`, etc.
- **MIME types**, `"text/plain"`, `"application/json"`, etc.
- **Framework identifiers**, `"UTF-8"`, `"SHA-256"`, `"GET"`, `"POST"`, etc.
- **XML namespaces**, `"http://schemas.android.com/apk/res/android"`, etc.
- **Common constants**, `"true"`, `"false"`, `"visible"`, `"gone"`, `"match_parent"`, etc.
- **Package prefixes**, `android.*`, `java.*`, `javax.*`, `kotlin.*`, `org.json.*`, etc.
- **Native library load calls**, `System.loadLibrary()` and `System.load()` arguments are never encrypted

This prevents crashes from encrypted framework constants like `Context.WINDOW_SERVICE` (which javac inlines as `"window"`).

## Control flow obfuscation

The plugin also includes a control flow obfuscation pass. When enabled, it injects opaque predicates before method calls and sensitive field access throughout the app's bytecode.

Each injection adds a conditional branch that always takes the same path:

```
sipush  22153       // random constant (always non-zero)
ifne    target      // always taken
goto    target      // dead path
target:
invokevirtual ...   // original instruction
```

Decompilers must render both branches, producing output like:

```java
if (22153 != 0) {
    super.onCreate(savedInstanceState);
} else {
    super.onCreate(savedInstanceState);
}
```

This multiplies the apparent complexity of every method. Combined with string encryption, the decompiled output becomes significantly harder to analyze.

Injection targets:
- **Method calls**, every `invokevirtual`, `invokestatic`, `invokeinterface` (except constructors)
- **Sensitive field access**, fields with names containing `url`, `token`, `key`, `secret`, `password`, or `api`

## Limitations

- **Compile-time constants only**, the plugin encrypts string literals that javac inlines as `LDC` instructions. Runtime-constructed strings (concatenation, `StringBuilder`) are not affected.
- **SharedPreferences**, if your app stores string keys in SharedPreferences, encrypting them means existing data is "lost" on upgrade (keys change from plaintext to encrypted). Users will need to re-login once.
- **Reflection**, strings passed to `Class.forName()`, `getMethod()`, etc. will break if encrypted. The skip list handles most common cases, but if you use reflection with custom class names, add them to the skip list or use `packages` to exclude those classes.
- **Build time**, ASM transformation adds a few seconds to the build. Only affects project classes (not library dependencies).
- **AGP required**, this plugin uses AGP's `AsmClassVisitorFactory` API for bytecode transformation. It requires the Android Gradle Plugin to be applied in the consuming project.

## Requirements

- Android Gradle Plugin (AGP) 8.0+ (uses `AsmClassVisitorFactory` API)
- CMake 3.22+ (for compiling the native decryption library)
- NDK (any recent version, for cross-compiling the `.so`)
- `src/main/cpp/` directory must exist in the app module

## License

[MIT](LICENSE)
