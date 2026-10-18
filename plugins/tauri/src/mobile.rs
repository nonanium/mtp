//! Install host callbacks from the application's native library initializer,
//! before Android can start the service, including after a cold boot.
use crate::{
    Manager,
    lifecycle::{BackgroundConnection, Lifecycle},
};
use jni::{
    JNIEnv,
    objects::{JClass, JString},
    sys::jboolean,
};
use std::sync::{Arc, OnceLock};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static OWNER: OnceLock<Arc<Lifecycle>> = OnceLock::new();

pub fn install(manager: Arc<Manager>) -> Result<Arc<Lifecycle>, String> {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("MTP runtime")
    });
    let owner = Lifecycle::new(manager);
    OWNER
        .set(owner.clone())
        .map_err(|_| "mobile runtime already installed")?;
    Ok(owner)
}

pub fn lifecycle() -> Option<Arc<Lifecycle>> {
    OWNER.get().cloned()
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nonanium_mtp_NativeBridge_start(
    mut env: JNIEnv,
    _: JClass,
    config: JString,
) -> jboolean {
    let result = (|| -> Result<(), String> {
        let config: String = env.get_string(&config).map_err(|e| e.to_string())?.into();
        let connections: Vec<BackgroundConnection> =
            serde_json::from_str(&config).map_err(|e| e.to_string())?;
        let owner = OWNER
            .get()
            .ok_or("host must install MTP runtime in native library initializer")?;
        RUNTIME
            .get()
            .ok_or("runtime missing")?
            .block_on(owner.start(connections))
    })();
    match result {
        Ok(()) => 1,
        Err(error) => {
            let _ = env.throw_new("java/lang/IllegalStateException", error);
            0
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_nonanium_mtp_NativeBridge_stop(_: JNIEnv, _: JClass) {
    if let (Some(runtime), Some(owner)) = (RUNTIME.get(), OWNER.get()) {
        runtime.block_on(owner.stop());
    }
}

#[cfg(all(feature = "tauri", target_os = "android"))]
pub fn register<R: tauri::Runtime>(
    api: &tauri::plugin::PluginApi<R, ()>,
) -> Result<tauri::plugin::PluginHandle<R>, Box<dyn std::error::Error>> {
    Ok(api.register_android_plugin("org.nonanium.mtp", "MtpPlugin")?)
}
