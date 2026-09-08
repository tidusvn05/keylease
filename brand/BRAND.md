# Leasegate brand system

Leasegate is the control boundary between people, agents, secrets, and tools.
The identity should feel precise and calm: access is intentionally opened,
scoped, observed, and closed again.

## Core idea

The symbol combines an open gateway with a mint access plane. The gate is the
durable policy boundary; the mint plane is the temporary capability moving
through it. The silhouette intentionally avoids the common padlock, shield,
key, robot, and chain-link motifs used by security and AI products.

## Naming

- Brand: `Leasegate` (capital L, otherwise lowercase)
- Desktop product: `KeyLease by Leasegate` when the parent brand needs context
- Mobile product: `Leasegate Approval`
- Do not write `LeaseGate`, `leaseGate`, or all-caps `LEASEGATE` in product UI.

## Palette

| Token | Hex | Use |
| --- | --- | --- |
| Midnight | `#071426` | App-icon field, dark surfaces, primary text |
| Gateway Blue | `#2F72FF` | Primary mark, actions, focus |
| Access Mint | `#36E3A2` | Granted/connected signal and mark accent |
| Cloud | `#F5F8FC` | Light background |
| Slate | `#5E6B7C` | Secondary text |
| Denied | `#FF5D6C` | Destructive and denied states only |
| Pending | `#FFBE55` | Pending approval only |

Use Access Mint as a semantic signal, not a general decoration. Never use red
or green alone to communicate state; retain a label or icon.

## Typography

- Product UI: system font (`SF Pro` on Apple platforms, `Roboto` on Android)
- Marketing and documentation: `Inter`
- Commands, identifiers, and code: `SF Mono`, then `JetBrains Mono`, monospace
- Prefer sentence case. Keep security copy direct and non-alarmist.

## Mark rules

- Minimum digital size: 16 px for the symbol, 120 px wide for the lockup.
- Clear space: at least one quarter of the symbol width on every side.
- Use the full-color symbol on Midnight, Cloud, white, or transparent fields.
- Use the monochrome symbol where color is unavailable.
- Do not rotate, outline, add gradients/shadows, recolor the mint plane, or put
  the symbol inside another shield, key, or badge.

## App icons

- macOS: rounded-square artwork with transparent corners. macOS adds no mask.
- iOS/iPadOS: full-bleed opaque square; the OS applies the final corner mask.
- Android: adaptive icon on supported launchers plus legacy PNG fallbacks.
- Web: standard and maskable 192/512 assets plus a 32 px favicon.

Run `./scripts/generate-brand-assets.sh` after changing a source SVG. Generated
PNG files are committed so Xcode, Android, and web builds do not depend on the
local SVG toolchain.

## Voice

Leasegate is concise, capable, and transparent about consequences.

- Prefer: `Allow once`, `Copy password`, `Vault locked`, `Open website`
- Avoid: vague labels such as `Continue`, exaggerated security claims, or
  implementation details users do not need to complete a task.
