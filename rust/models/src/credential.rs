// SPDX-FileCopyrightText: 2023 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later

/// Represents a set of credentials to be used for scanning to access a host.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub struct Credential {
    /// Service to use for accessing a host
    pub service: Service,
    /// Port used for getting access. If missing a standard port is used
    pub port: Option<u16>,
    #[cfg_attr(feature = "serde_support", serde(flatten))]
    /// Type of the credential to get access. Different services support different types.
    pub credential_type: CredentialType,
}

/// Enum of available services
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
pub enum Service {
    #[cfg_attr(feature = "serde_support", serde(rename = "ssh"))]
    /// SSH, supports [UP](CredentialType::UP) and [USK](CredentialType::USK) as credential types
    SSH,
    #[cfg_attr(feature = "serde_support", serde(rename = "smb"))]
    /// SMB, supports [UP](CredentialType::UP)
    SMB,
    #[cfg_attr(feature = "serde_support", serde(rename = "esxi"))]
    /// ESXi, supports [UP](CredentialType::UP)
    ESXi,
    #[cfg_attr(feature = "serde_support", serde(rename = "snmp"))]
    /// SNMP, supports [SNMP](CredentialType::SNMP)
    SNMP,
}

impl AsRef<str> for Service {
    fn as_ref(&self) -> &str {
        match self {
            Service::SSH => "ssh",
            Service::SMB => "smb",
            Service::ESXi => "esxi",
            Service::SNMP => "snmp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde_support",
    derive(serde::Serialize, serde::Deserialize)
)]
/// Enum representing the type of credentials.
pub enum CredentialType {
    #[cfg_attr(feature = "serde_support", serde(rename = "up"))]
    /// User/password credentials.
    UP {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
    },
    #[cfg_attr(feature = "serde_support", serde(rename = "usk"))]
    /// User/ssh-key credentials.
    USK {
        /// The username for authentication.
        username: String,
        /// The password for authentication.
        password: String,
        #[cfg_attr(feature = "serde_support", serde(rename = "private"))]
        /// The private key for authentication.
        private_key: String,
    },
    #[cfg_attr(feature = "serde_support", serde(rename = "snmp"))]
    /// SNMP credentials.
    SNMP {
        /// The SNMP username.
        username: String,
        /// The SNMP password.
        password: String,
        /// The SNMP community string.
        community: String,
        /// The SNMP authentication algorithm.
        auth_algorithm: String,
        /// The SNMP privacy password.
        privacy_password: String,
        /// The SNMP privacy algorithm.
        privacy_algorithm: String,
    },
}

impl AsRef<str> for CredentialType {
    fn as_ref(&self) -> &str {
        match self {
            CredentialType::UP { .. } => "up",
            CredentialType::USK { .. } => "usk",
            CredentialType::SNMP { .. } => "snmp",
        }
    }
}

impl CredentialType {
    /// Replace all sensitive data related to credentials with asterisks.
    /// It is intended to be used before print/debug the credentials setup to
    /// prevent showing them.
    /// Consider to clone the credentials before using this method, for further credentials usage.
    pub fn hide_sensitive_data (&mut self) -> Self {
        match self {
            CredentialType::UP {username: _, password: _ } =>
                CredentialType::UP { username: "*".to_owned(), password: "*".to_owned() },
            CredentialType::USK { username: _, password: _, private_key: _ } =>
                CredentialType::USK {
                    username: "*".to_owned(),
                    password: "*".to_owned(),
                    private_key: "*".to_owned()
                },
            CredentialType::SNMP {
                username: _,
                password: _,
                community: _,
                auth_algorithm: _,
                privacy_password: _,
                privacy_algorithm: _
            } =>
                CredentialType::SNMP { username: "*".to_owned(), password: "*".to_owned(), community: "*".to_owned(), auth_algorithm: "*".to_owned(), privacy_password: "*".to_owned(), privacy_algorithm: "*".to_owned() }
        }
    }
}
