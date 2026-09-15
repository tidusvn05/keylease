plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "ai.leasegate.mobile"
    compileSdk = 36

    // Pinned to the same NDK `cargo ndk` builds libkeylease_mobile.so
    // against; see the comment in apps/mobile-flutter for why this cannot
    // float.
    ndkVersion = "28.2.13676358"

    defaultConfig {
        // Parallel-installable with the Flutter client (ai.leasegate.vault).
        applicationId = "ai.leasegate.mobile"
        minSdk = 26
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        ndk {
            // Same constraint as the Flutter client: arm64 for devices,
            // x86_64 for emulators; Argon2id's 64 MiB makes armeabi-v7a an
            // OOM risk for a marginal device population.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
            // No fallback signing config on purpose: the repository never
            // materialises a debug key into a release artifact. Sign where
            // the key lives, as with the Flutter client.
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

/**
 * Rebuilds the Rust core before every Android build, for the same reason the
 * Flutter client does: a stale .so silently packaged from jniLibs is the
 * classic cargo-ndk failure. KEYLEASE_ANDROID_FEATURES turns on the JNI
 * exports this app binds; KEYLEASE_SKIP_RUST=1 reuses the staged .so when
 * only Kotlin changed.
 */
val buildRustCore by tasks.registering(Exec::class) {
    // apps/mobile-android -> apps -> repository root.
    workingDir = rootProject.projectDir.parentFile.parentFile
    environment(
        "KEYLEASE_ANDROID_OUTPUT_DIR",
        layout.projectDirectory.dir("src/main/jniLibs").asFile.absolutePath,
    )
    environment("KEYLEASE_ANDROID_FEATURES", "jni")
    commandLine("bash", "scripts/build-android-rust.sh")
    isIgnoreExitValue = false
    onlyIf { System.getenv("KEYLEASE_SKIP_RUST") != "1" }
}

tasks.named("preBuild") { dependsOn(buildRustCore) }

dependencies {
    // Compose 1.12 (BOM 2026.08+) requires compileSdk 37; AGP 9.1.0 caps at
    // 36, so stay on the last BOM line that targets SDK 36.
    val composeBom = platform("androidx.compose:compose-bom:2025.12.00")
    implementation(composeBom)

    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.activity:activity-compose:1.11.0")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.4")
    implementation("androidx.lifecycle:lifecycle-process:2.9.4")

    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.2")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-play-services:1.10.2")

    // BiometricPrompt + AndroidKeyStore-backed password cache.
    implementation("androidx.biometric:biometric:1.1.0")

    // TOTP QR capture: camera preview (CameraX) and on-device decoding
    // (ML Kit). Nothing leaves the process; no network permission is added
    // for these.
    implementation("androidx.camera:camera-core:1.5.0")
    implementation("androidx.camera:camera-camera2:1.5.0")
    implementation("androidx.camera:camera-lifecycle:1.5.0")
    implementation("androidx.camera:camera-view:1.5.0")
    implementation("com.google.mlkit:barcode-scanning:17.3.0")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.10.2")
    testImplementation("org.robolectric:robolectric:4.16")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
}
