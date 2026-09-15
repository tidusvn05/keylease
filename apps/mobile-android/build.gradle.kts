plugins {
    id("com.android.application") version "9.1.0" apply false
    // AGP 9 bundles Kotlin (KGP) itself — the org.jetbrains.kotlin.android
    // plugin must not be applied to modules. The Compose compiler plugin is
    // still separate.
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.0" apply false
}
