use asym_ratchet::{PrivateKey, PublicKey, RatchetError};
use jni::{
    objects::{JByteArray, JClass, JLongArray, JObject},
    sys::jlong,
    JNIEnv,
};
use serde::Serialize;
use rand::thread_rng;

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
    let keypair = asym_ratchet::generate_keypair(thread_rng());

    let pubkey = Box::leak(Box::new(keypair.0));
    let privkey = Box::leak(Box::new(keypair.1));

    let jarray = env.new_long_array(2).unwrap();
    env.set_long_array_region(
        &jarray,
        0,
        &[pubkey as *mut _ as jlong, privkey as *mut _ as jlong],
    )
    .unwrap();
    jarray
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_keypair_1generate_1epoch<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    epoch: jlong,
) -> JLongArray<'local> {
    let Ok(epoch) = epoch.try_into() else {
        env.throw_new(RATCHET_EXCEPTION, "Epoch is negative").unwrap();
        return JObject::null().into();
    };
    let keypair = asym_ratchet::generate_keypair_in_epoch(thread_rng(), epoch);

    let pubkey = Box::leak(Box::new(keypair.0));
    let privkey = Box::leak(Box::new(keypair.1));

    let jarray = env.new_long_array(2).unwrap();
    env.set_long_array_region(
        &jarray,
        0,
        &[pubkey as *mut _ as jlong, privkey as *mut _ as jlong],
    )
    .unwrap();
    jarray
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1ratchet<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
    // I don't think we will ever reach this but let's better be safe than sorry
    if let Err(RatchetError::Exhausted) = pubkey.ratchet() {
        env.throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
            .unwrap();
    }
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1encrypt<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    payload: JByteArray<'local>,
) -> JByteArray<'local> {
    let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
    let buf = bytearray_as_vec(&env, payload);
    let encrypted = pubkey.encrypt(thread_rng(), buf).unwrap();
    serialize_as_bytearray(&env, &encrypted)
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1serialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> JByteArray<'local> {
    let pubkey: &mut PublicKey = unsafe { &mut *(pointer as *mut _) };
    serialize_as_bytearray(&env, &pubkey)
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_pubkey_1deserialize<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data: JByteArray<'local>,
) -> jlong {
    let buf = bytearray_as_vec(&env, data);
    let key: Result<PublicKey, _> = bincode::deserialize(&buf);

    match key {
        Ok(key) => {
            let pointer = Box::leak(Box::new(key));
            pointer as *mut _ as jlong
        }
        Err(err) => {
            env.throw_new(RATCHET_EXCEPTION, format!("Could not deserialize public key: {}", err))
                .unwrap();
            0
        }
    }
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
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
    if let Err(RatchetError::Exhausted) = privkey.ratchet(thread_rng()) {
        env.throw_new(RATCHET_EXCEPTION, "Ratchet is exhausted")
            .unwrap();
    }
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1decrypt<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
    ciphertext: JByteArray<'local>,
) -> JByteArray<'local> {
    let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
    let buf = bytearray_as_vec(&env, ciphertext);

    let Ok(ciphertext) = bincode::deserialize(&buf) else {
        env.throw_new(RATCHET_EXCEPTION, "Invalid ciphertext").unwrap();
        return JObject::null().into();
    };

    let decrypted = privkey.decrypt(ciphertext).unwrap();
    slice_as_bytearray(&env, &decrypted)
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1serialize<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) -> JByteArray<'local> {
    let privkey: &mut PrivateKey = unsafe { &mut *(pointer as *mut _) };
    serialize_as_bytearray(&env, &privkey)
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1deserialize<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    data: JByteArray<'local>,
) -> jlong {
    let buf = bytearray_as_vec(&env, data);
    let key: Result<PrivateKey, _> = bincode::deserialize(&buf);

    match key {
        Ok(key) => {
            let pointer = Box::leak(Box::new(key));
            pointer as *mut _ as jlong
        }
        Err(err) => {
            env.throw_new(RATCHET_EXCEPTION, format!("Could not deserialize private key: {}", err))
                .unwrap();
            0
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_edu_kit_tm_ps_Sys_privkey_1drop<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    pointer: jlong,
) {
    unsafe { Box::from_raw(pointer as *mut PrivateKey) };
}
