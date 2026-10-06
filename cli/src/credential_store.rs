use crate::Result;
use zeroize::Zeroizing;

pub struct CredentialStore {
    entry: keyring::Entry,
}

impl CredentialStore {
    pub fn new(server: &str) -> Result<Self> {
        Ok(Self {
            entry: keyring::Entry::new("voe-cli", server)?,
        })
    }

    #[cfg(test)]
    pub fn load(&self) -> Result<Zeroizing<String>> {
        self.load_optional()?.ok_or_else(|| "No credential-store entry. Run ve auth for this server. No plaintext fallback is used.".into())
    }

    pub fn load_optional(&self) -> Result<Option<Zeroizing<String>>> {
        match self.entry.get_password() {
            Ok(value) => Ok(Some(Zeroizing::new(value))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(error) => Err(format!(
                "Could not read credentials from the OS credential store: {error}"
            )
            .into()),
        }
    }

    pub fn save(&self, value: &str) -> Result<()> {
        self.entry.set_password(value).map_err(|error| {
            format!("Could not store credentials in the OS credential store: {error}").into()
        })
    }

    pub fn delete(&self) -> Result<()> {
        self.entry.delete_credential().map_err(|error| {
            format!("Could not remove credentials from the OS credential store: {error}").into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn store() -> CredentialStore {
        CredentialStore {
            entry: keyring::Entry::new_with_credential(Box::new(
                keyring::mock::MockCredential::default(),
            )),
        }
    }

    #[test]
    fn credentials_can_be_saved_loaded_replaced_and_deleted() {
        let store = store();
        store.save("original").unwrap();
        assert_eq!(&*store.load().unwrap(), "original");
        store.save("replacement").unwrap();
        assert_eq!(&*store.load().unwrap(), "replacement");
        store.delete().unwrap();
        assert!(matches!(
            store.entry.get_password(),
            Err(keyring::Error::NoEntry)
        ));
    }

    #[test]
    fn credential_store_errors_are_not_reported_as_missing_credentials() {
        let store = store();
        let mock = store
            .entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .unwrap();
        mock.set_error(keyring::Error::Invalid("access".into(), "denied".into()));
        let error = store.load().unwrap_err().to_string();
        assert!(error.contains("denied"));
        assert!(!error.contains("Run ve auth"));
        assert!(store
            .load()
            .unwrap_err()
            .to_string()
            .contains("Run ve auth"));
    }
}
