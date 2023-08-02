use libc::{c_int, c_uint, size_t};

extern "C" {
    fn nasl_aes_mac_gcm(
        data: *const u8,
        datalen: size_t,
        key: *const u8,
        keylen: size_t,
        iv: *const u8,
        ivlen: size_t,
        out: *mut u8,
    ) -> c_int;
    fn get_aes_mac_gcm_len() -> c_uint;
}

pub fn aes_mac_gcm(data: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, i32> {
    unsafe {
        // let mut ret = data.to_vec();
        let mut ret: Vec<u8> = Vec::with_capacity(get_aes_mac_gcm_len() as usize);
        let out = ret.as_mut_ptr();
        let err = nasl_aes_mac_gcm(
            data.as_ptr(),
            data.len(),
            key.as_ptr(),
            key.len(),
            iv.as_ptr(),
            iv.len(),
            out,
        );
        if err != 0 {
            return Err(err);
        }
        Ok(ret)
    }
}
