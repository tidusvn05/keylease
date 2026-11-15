# KeyLease Android design system (Compose)

The [KeyLease Android design system](https://claude.ai/artifact/5KoRdgxq9yCqR1hUcs5MRQ) as an Android library module:
tokens, `KeyleaseTheme`, and the components of the app, for Jetpack Compose on
Material 3. `tokens.json` beside this file holds the values; the Kotlin
matches it exactly.

Same toolchain as `apps/mobile-android`: AGP 9.1.0, Kotlin Compose plugin
2.4.0, Compose BOM 2025.12.00, compileSdk 36, minSdk 26, JVM 17.

## Layout

```text
designsystem/src/main/kotlin/ai/keylease/designsystem/
├── Color.kt        KeyleaseBrand (fixed brand colors), KeyleaseColors (roles), light + dark
├── Type.kt         KeyleaseTypography (Material 3 scale), mono styles
├── Dimens.kt       KeyleaseSpacing, KeyleaseSize, KeyleaseRadius, KeyleaseShapes
├── Theme.kt        KeyleaseTheme { } and the Material ColorScheme mapping
├── Previews.kt     @Preview galleries, light and dark
└── components/
    ├── Buttons.kt   KeyleaseButton (filled / outlined / text), ButtonRow, FavoriteToggle
    ├── Feedback.kt  MessageBanner, StateScreen
    ├── Vault.kt     SecretField, Monogram, SectionLabel, SelectField
    └── Approval.kt  ApprovalCard, RiskChip, ApprovalDecisionDialog
```

## Use it in an app

`settings.gradle.kts` of the app:

```kotlin
include(":designsystem")
project(":designsystem").projectDir = file("../android-designsystem/designsystem")
```

The app module: `implementation(project(":designsystem"))`, then

```kotlin
setContent {
    KeyleaseTheme {
        // Material components already use the KeyLease roles.
        // Roles Material has no slot for:
        Text("Connected", color = KeyleaseTheme.colors.success)
        Text(digest, style = KeyleaseTheme.text.monoSmall)
    }
}
```

## How Material slots map

| Material slot | KeyLease role |
|---|---|
| `primary` / `onPrimary` | `primary` / `onPrimary` |
| `background` / `onBackground` | `background` / `ink` |
| `surface`, `surfaceVariant`, `surfaceDim` / `onSurface` | `surface` / `ink` |
| `surfaceContainer*`, `surfaceBright` | `surfaceRaised` (lowest: `background`) |
| `onSurfaceVariant`, `secondary` | `onSurfaceVariant` |
| `outline` / `outlineVariant` | `outline` / `outlineVariant` |
| `error` / `errorContainer` | `danger` / `dangerContainer` |
| `primaryContainer`, `secondaryContainer` | `markSurface` |
| `tertiary` / `tertiaryContainer` | `success` / `successContainer` |
| `surfaceTint` | `surface` (no tonal elevation tint) |

`warning`, `warningContainer`, `markForeground`, `focusRing` have no Material
slot: read them from `KeyleaseTheme.colors`.

## Not done yet

- **Not built.** This machine has no JDK or Android SDK. Build it once with
  `./gradlew :designsystem:assembleDebug` and open `Previews.kt` in Android
  Studio.
- JetBrains Mono is not bundled; `KeyleaseMonoFamily` is the platform
  monospace until `res/font/jetbrains_mono_regular.ttf` is added (see `Type.kt`).
- `apps/mobile-android` still uses its own `ui/Theme.kt` and
  `ui/Components.kt`; nothing there was changed.
