use std::sync::Mutex;

use asym_ratchet::{PrivateKey, PublicKey, RatchetError};
use jni::{
    objects::{JByteArray, JClass, JLongArray, JObject},
    sys::jlong,
    JNIEnv,
};
use serde::Serialize;
use rand::thread_rng;

macro_rules! panic_guard {
    (#, $env:ident, $name:expr, $body:expr) => {
        panic_guard!(JObject::default().into(), $env, $name, $body)
    };
    ($env:ident, $name:expr, $body:expr) => {
        panic_guard!((), $env, $name, $body)
    };
    ($default:expr, $env:ident, $name:expr, $body:expr) => {
        {
            let $env = &Mutex::new($env);
            let panic = ::std::panic::catch_unwind(move || $body);
            match panic {
                Ok(value) => value,
                Err(e) => {
                    let panic_str = e.downcast_ref::<&'static str>()
                        .map(|s| *s)
                        .or_else(|| e.downcast_ref::<String>().map(String::as_str))
                        .unwrap_or("<unknown panic>");
                    $env.lock()
                        .unwrap()
                        .throw_new(RATCHET_EXCEPTION, format!("{} panic'd: {}", $name, panic_str))
                        .unwrap();
                    $default
                }
            }
        }
    };
}

const RATCHET_EXCEPTION: &str = "edu/kit/tm/ps/RatchetException";

fn serialize_as_bytearray<'a, T: Serialize>(env: &JNIEnv<'a>, obj: &T) -> JByteArray<'a> {
    let serialized = bincode::serialize(obj).unwrap();
    slice_as_bytearray(env, &serialized)
}

fn slice_as_bytearray<'a>(env: &JNIEnv<'a>, sl: &[u8]) -> JByteArray<'a> {
    let result = env.new_byte_array(sl.len() as i32).unwrap();
    env.set_byte_array_region(&result, 0, bytemuck::cast_slice(&sl))
        .unwrap();
    result
}

fn bytearray_as_vec(env: &JNIEnv, array: JByteArray) -> Vec<u8> {
    let mut buf = vec![0u8; env.get_array_length(&array).unwrap() as usize];
    env.get_byte_array_region(&array, 0, bytemuck::cast_slice_mut(&mut buf))
        .unwrap();
    buf
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_keypair_1generate<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> JLongArray<'local> {
    panic_guard!(#, env, "keypair_generate", {
        let keypair = asym_ratchet::generate_keypair(thread_rng());

        let pubkey = Box::leak(Box::new(keypair.0));
        let privkey = Box::leak(Box::new(keypair.1));

        let jarray = env.lock().unwrap().new_long_array(2).unwrap();
        env.lock()
            .unwrap()
            .set_long_array_region(
                &jarray,
                0,
                &[pubkey as *mut _ as jlong, privkey as *mut _ as jlong],
            )
            .unwrap();
        jarray
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_keypair_1generate_1epoch<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    epoch: jlong,
) -> JLongArray<'local> {
    panic_guard!(#, env, "keypair_generate_epoch", {
        let Ok(epoch) = epoch.try_into() else {
            env.lock().unwrap().throw_new(RATCHET_EXCEPTION, "Epoch is negative").unwrap();
            return JObject::null().into();
        };
        let keypair = asym_ratchet::generate_keypair_in_epoch(thread_rng(), epoch);

        let pubkey = Box::leak(Box::new(keypair.0));
        let privkey = Box::leak(Box::new(keypair.1));

        let jarray = env.lock().unwrap().new_long_array(2).unwrap();
        env.lock()
            .unwrap()
            .set_long_array_region(
                &jarray,
                0,
                &[pubkey as *mut _ as jlong, privkey as *mut _ as jlong],
            )
            .unwrap();
        jarray
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1ratchet<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    panic_guard!(env, "pubkey_ratchet", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        // I don't think we will ever reach this but let's better be safe than sorry
        if let Err(RatchetError::Exhausted) = pubkey.ratchet() {
            env.lock()
                .unwrap()
                .throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
                .unwrap();
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1fast_1forward<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    count: jlong,
) {
    panic_guard!(env, "pubkey_fast_forward", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        if let Err(RatchetError::Exhausted) = pubkey.fast_forward(count.try_into().unwrap()) {
            env.lock()
                .unwrap()
                .throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
                .unwrap();
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1encrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    payload: JByteArray<'local>,
) -> JByteArray<'local> {
    panic_guard!(#, env, "pubkey_encrypt", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        let buf = bytearray_as_vec(&env.lock().unwrap(), payload);
        let encrypted = pubkey.encrypt(thread_rng(), buf).unwrap();
        serialize_as_bytearray(&env.lock().unwrap(), &encrypted)
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1serialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> JByteArray<'local> {
    panic_guard!(#, env, "pubkey_serialize", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        serialize_as_bytearray(&env.lock().unwrap(), &pubkey)
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1deserialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    data: JByteArray<'local>,
) -> jlong {
    panic_guard!(0, env, "pubkey_deserialize", {
        let buf = bytearray_as_vec(&env.lock().unwrap(), data);
        let key: Result<PublicKey, _> = bincode::deserialize(&buf);

        match key {
            Ok(key) => {
                let pointer = Box::leak(Box::new(key));
                pointer as *mut _ as jlong
            }
            Err(err) => {
                env.lock()
                    .unwrap()
                    .throw_new(RATCHET_EXCEPTION, format!("Could not deserialize public key: {}", err))
                    .unwrap();
                0
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1clone<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> jlong {
    panic_guard!(0, env, "pubkey_clone", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        Box::leak(Box::new(pubkey.clone())) as *mut _ as jlong
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1current_1epoch<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> jlong {
    panic_guard!(0, env, "pubkey_current_epoch", {
        let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
        pubkey.current_epoch().try_into().unwrap()
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1drop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    unsafe { Box::from_raw(pointer as *mut PublicKey) };
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1ratchet<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    panic_guard!(env, "privkey_ratchet", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        if let Err(RatchetError::Exhausted) = privkey.ratchet(thread_rng()) {
            env.lock()
                .unwrap()
                .throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
                .unwrap();
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1fast_1forward<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    count: jlong,
) {
    panic_guard!(env, "privkey_fast_forward", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        if let Err(RatchetError::Exhausted) = privkey.fast_forward(thread_rng(), count.try_into().unwrap()) {
            env.lock()
                .unwrap()
                .throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
                .unwrap();
        }
    });
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1decrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    ciphertext: JByteArray<'local>,
) -> JByteArray<'local> {
    panic_guard!(#, env, "privkey_decrypt", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        let buf = bytearray_as_vec(&env.lock().unwrap(), ciphertext);

        let Ok(ciphertext) = bincode::deserialize(&buf) else {
            env.lock().unwrap().throw_new(RATCHET_EXCEPTION, "Invalid ciphertext").unwrap();
            return JObject::null().into();
        };

        let decrypted = privkey.decrypt(ciphertext).unwrap();
        slice_as_bytearray(&env.lock().unwrap(), &decrypted)
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1serialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> JByteArray<'local> {
    panic_guard!(#, env, "privkey_serialize", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        serialize_as_bytearray(&env.lock().unwrap(), &privkey)
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1deserialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    data: JByteArray<'local>,
) -> jlong {
    panic_guard!(0, env, "privkey_deserialize", {
        let buf = bytearray_as_vec(&env.lock().unwrap(), data);
        let key: Result<PrivateKey, _> = bincode::deserialize(&buf);

        match key {
            Ok(key) => {
                let pointer = Box::leak(Box::new(key));
                pointer as *mut _ as jlong
            }
            Err(err) => {
                env.lock()
                    .unwrap()
                    .throw_new(RATCHET_EXCEPTION, format!("Could not deserialize private key: {}", err))
                    .unwrap();
                0
            }
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1clone<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> jlong {
    panic_guard!(0, env, "privkey_clone", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        Box::leak(Box::new(privkey.clone())) as *mut _ as jlong
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1current_1epoch<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> jlong {
    panic_guard!(0, env, "privkey_current_epoch", {
        let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
        privkey.current_epoch().try_into().unwrap()
    })
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1drop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    unsafe { Box::from_raw(pointer as *mut PrivateKey) };
}
