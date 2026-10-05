use crate::Result;

pub trait Authorization {
    fn authorize(&self, reason: &str) -> Result<()>;
}

pub struct NativeAuthorization;

impl Authorization for NativeAuthorization {
    fn authorize(&self, reason: &str) -> Result<()> {
        authorize(reason)
    }
}

#[cfg(not(target_os = "macos"))]
fn authorize(_reason: &str) -> Result<()> {
    Ok(())
}

#[cfg(target_os = "macos")]
fn authorize(reason: &str) -> Result<()> {
    use block2::RcBlock;
    use objc2::{rc::autoreleasepool, runtime::Bool};
    use objc2_foundation::{NSError, NSString};
    use objc2_local_authentication::{LAContext, LAPolicy};
    use std::{sync::mpsc, time::Duration};

    autoreleasepool(|_| {
        let context = unsafe { LAContext::new() };
        let policy = LAPolicy::DeviceOwnerAuthentication;
        unsafe { context.canEvaluatePolicy_error(policy) }
            .map_err(|error| authentication_error(&error))?;

        let (sender, receiver) = mpsc::sync_channel(1);
        let reply = RcBlock::new(move |success: Bool, error: *mut NSError| {
            let result = if success.as_bool() {
                Ok(())
            } else {
                Err(unsafe { error.as_ref() }
                    .map(authentication_error)
                    .unwrap_or_else(|| "macOS authentication was not approved.".into()))
            };
            let _ = sender.try_send(result);
        });
        unsafe {
            context.evaluatePolicy_localizedReason_reply(
                policy,
                &NSString::from_str(reason),
                &reply,
            );
        }
        let result = receiver.recv_timeout(Duration::from_secs(120));
        unsafe { context.invalidate() };
        match result {
            Ok(result) => result.map_err(Into::into),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                Err("macOS authentication timed out. Run the command again.".into())
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                Err("macOS authentication ended without approval.".into())
            }
        }
    })
}

#[cfg(target_os = "macos")]
fn authentication_error(error: &objc2_foundation::NSError) -> String {
    use objc2_local_authentication::{LAError, LAErrorDomain};

    if &*error.domain() == unsafe { LAErrorDomain }
        && matches!(
            LAError(error.code()),
            LAError::UserCancel | LAError::SystemCancel | LAError::AppCancel
        )
    {
        "macOS authentication cancelled. No credentials were accessed.".into()
    } else {
        format!(
            "macOS authentication failed: {}",
            error.localizedDescription()
        )
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    #[ignore = "Requires a person to approve the macOS authentication dialog"]
    fn native_authentication_succeeds() {
        authorize("test authentication (use Touch ID or your Mac password)").unwrap();
    }

    #[test]
    #[ignore = "Requires a person to cancel the macOS authentication dialog"]
    fn native_authentication_cancelled() {
        let error = authorize("test cancellation (choose Cancel)").unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
    }
}
