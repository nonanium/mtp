# Android sources

The files under `.tauri/tauri-api/`, including `src/main/java/app/tauri/`, are local copies of Tauri's upstream Android runtime used for Android compilation. They are dependency sources, not handwritten MTP code or generated MTP logic. Treat them as disposable build support and do not edit them to change this plugin. Normal Tauri host builds supply the `:tauri-android` dependency.

The MTP-specific Kotlin under `src/main/java/org/nonanium/mtp/` is handwritten and maintained here. It implements Android service lifecycle, notifications, Keystore storage, and the bridge to Rust.
