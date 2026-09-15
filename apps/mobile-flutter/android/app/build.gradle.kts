plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "ai.leasegate.vault"
    compileSdk = flutter.compileSdkVersion

    // Pinned rather than inherited from `flutter.ndkVersion` so that the NDK
    // Gradle uses is provably the same one `cargo ndk` built libkeylease_mobile
    // against. A mismatch surfaces as libc++_shared symbol errors that are
    // miserable to diagnose.
    ndkVersion = "28.2.13676358"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "ai.leasegate.vault"

        // 26 for adaptive launcher icons and a sane BiometricPrompt. The Rust
        // core is built for android-24, so this is the stricter of the two.
        minSdk = 26
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        ndk {
            // arm64 for devices, x86_64 for emulators. armeabi-v7a is a
            // deliberate non-goal: Argon2id wants 64 MiB, and asking for that
            // in a 32-bit address space alongside Flutter's own heap is a real
            // OOM risk for a marginal device population.
            //
            // This constrains jniLibs (libkeylease_mobile.so). It does NOT
            // constrain Flutter's own engine libraries — measured: a release
            // build still packaged armeabi-v7a until the build was invoked with
            // `--target-platform android-arm64,android-x64`, which took the APK
            // from 56.4 MB to 40.2 MB. scripts/build-android.sh passes it.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            // Release signing is intentionally supplied by the operator's CI or
            // local Android keystore configuration. Never ship a debug-signed
            // APK: the template's `signingConfigs.getByName("debug")` line is
            // removed on purpose, and `flutter build apk --release` is expected
            // to emit an unsigned artifact.
        }
    }
}

dependencies {
    implementation("androidx.biometric:biometric:1.1.0")
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

/**
 * Rebuilds the Rust core before every Android build.
 *
 * Without this, `flutter build apk` happily packages whatever
 * libkeylease_mobile.so happens to be sitting in jniLibs — including one from
 * a previous revision — and you end up debugging a protocol mismatch that does
 * not exist in the source. That is the classic cargo-ndk failure, so the
 * dependency is mandatory rather than a convenience.
 *
 * Set KEYLEASE_SKIP_RUST=1 to build the Dart side alone (useful when only the
 * UI changed, and on a machine without the NDK).
 */
val buildRustCore by tasks.registering(Exec::class) {
    workingDir = rootProject.projectDir.parentFile.parentFile.parentFile
    commandLine("bash", "scripts/build-android-rust.sh")
    isIgnoreExitValue = false
    onlyIf { System.getenv("KEYLEASE_SKIP_RUST") != "1" }
}

tasks.named("preBuild") { dependsOn(buildRustCore) }
