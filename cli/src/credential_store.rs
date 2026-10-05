use crate::{
    local_auth::{Authorization, NativeAuthorization},
    Result,
};
use zeroize::Zeroizing;

pub struct CredentialStore<A = NativeAuthorization> {
    entry: keyring::Entry,
    authorization: A,
}

impl CredentialStore {
    pub fn new(server: &str) -> Result<Self> {
        Ok(Self {
            entry: keyring::Entry::new("voe-cli", server)?,
            authorization: NativeAuthorization,
        })
    }
}

impl<A: Authorization> CredentialStore<A> {
    pub fn load(&self) -> Result<Zeroizing<String>> {
        self.authorization
            .authorize("access your workspace credentials")?;
        match self.entry.get_password() {
            Ok(value) => Ok(Zeroizing::new(value)),
            Err(keyring::Error::NoEntry) => {
                Err("No credential-store entry. Run ve auth for this server. No plaintext fallback is used.".into())
            }
            Err(error) => Err(format!("Could not read credentials from the OS credential store: {error}").into()),
        }
    }

    pub fn save(&self, value: &str) -> Result<()> {
        self.authorization
            .authorize("store your workspace credentials")?;
        self.entry.set_password(value).map_err(|error| {
            format!("Could not store credentials in the OS credential store: {error}").into()
        })
    }

    pub fn delete(&self) -> Result<()> {
        self.authorization
            .authorize("remove your workspace credentials")?;
        self.entry.delete_credential().map_err(|error| {
            format!("Could not remove credentials from the OS credential store: {error}").into()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct TestAuthorization {
        approved: bool,
        calls: Cell<usize>,
    }

    impl Authorization for TestAuthorization {
        fn authorize(&self, _reason: &str) -> Result<()> {
            self.calls.set(self.calls.get() + 1);
            if self.approved {
                Ok(())
            } else {
                Err("Authentication cancelled".into())
            }
        }
    }

    fn store(approved: bool) -> CredentialStore<TestAuthorization> {
        CredentialStore {
            entry: keyring::Entry::new_with_credential(Box::new(
                keyring::mock::MockCredential::default(),
            )),
            authorization: TestAuthorization {
                approved,
                calls: Cell::new(0),
            },
        }
    }

    #[test]
    fn cancelled_authentication_prevents_read_write_and_delete() {
        let store = store(false);
        store.entry.set_password("original").unwrap();
        let mock = store
            .entry
            .get_credential()
            .downcast_ref::<keyring::mock::MockCredential>()
            .unwrap();
        mock.set_error(keyring::Error::Invalid(
            "store".into(),
            "must not be accessed".into(),
        ));
        for result in [
            store.load().map(|_| ()),
            store.save("replacement"),
            store.delete(),
        ] {
            assert_eq!(result.unwrap_err().to_string(), "Authentication cancelled");
        }
        assert_eq!(store.authorization.calls.get(), 3);
        assert!(store
            .entry
            .get_password()
            .unwrap_err()
            .to_string()
            .contains("must not be accessed"));
        assert_eq!(store.entry.get_password().unwrap(), "original");
    }

    #[test]
    fn every_credential_operation_requires_fresh_authorization() {
        let store = store(true);
        store.save("original").unwrap();
        assert_eq!(&*store.load().unwrap(), "original");
        store.save("replacement").unwrap();
        assert_eq!(&*store.load().unwrap(), "replacement");
        store.delete().unwrap();
        assert!(matches!(
            store.entry.get_password(),
            Err(keyring::Error::NoEntry)
        ));
        assert_eq!(store.authorization.calls.get(), 5);
    }

    #[test]
    fn credential_store_errors_are_not_reported_as_missing_credentials() {
        let store = store(true);
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
