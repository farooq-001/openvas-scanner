// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

use nasl_builtin_utils::error::GeneralErrorType;
use nasl_builtin_utils::{Context, FunctionErrorKind, Register};
use nasl_c_lib::nasl_aes_mac_gcm::aes_mac_gcm;
use nasl_syntax::NaslValue;

use crate::{get_data, get_iv, get_key, NaslFunction};

/// NASL function to calculate CMAC wit AES128.
///
/// This function expects 2 named arguments key and data either in a string or data type.
/// It is important to notice, that internally the CMAC algorithm is used and not, as the name
/// suggests, CBC-MAC.
fn aes_gmac<K>(register: &Register, _: &Context<K>) -> Result<NaslValue, FunctionErrorKind> {
    let key = get_key(register)?;
    let data = get_data(register)?;
    let iv = get_iv(register)?;

    match aes_mac_gcm(data, key, iv) {
        Ok(val) => Ok(val.into()),
        Err(code) => Err(FunctionErrorKind::GeneralError(
            GeneralErrorType::UnexpectedData(format!("Error code {}", code)),
        )),
    }
}

pub fn lookup<K>(key: &str) -> Option<NaslFunction<K>> {
    match key {
        "aes_mac_gcm" => Some(aes_gmac),
        "aes_gmac" => Some(aes_gmac),
        _ => None,
    }
}
