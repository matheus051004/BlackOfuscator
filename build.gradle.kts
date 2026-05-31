plugins {
    `java-gradle-plugin`
    kotlin("jvm") version "2.3.0"
    `maven-publish`
}

group = "io.github.matheus"
version = "1.0.0"

repositories {
    mavenCentral()
    google()
}

dependencies {
    implementation("org.ow2.asm:asm-util:9.7.1")
    // AGP is required at compile time for the AsmClassVisitorFactory API,
    // but the consumer provides their own AGP version at runtime.
    compileOnly("com.android.tools.build:gradle:9.2.1")
}

gradlePlugin {
    website.set("https://github.com/matheus051004/BlackOfuscator")
    vcsUrl.set("https://github.com/matheus051004/BlackOfuscator")
    plugins {
        create("stringEncrypt") {
            id = "string-encrypt"
            implementationClass = "StringEncryptPlugin"
            displayName = "BlackOfuscator"
            description = "Android Gradle plugin that encrypts string literals via ASM bytecode transformation with JNI-based native decryption"
        }
    }
}


