//! The SQLite stores that older packages kept beside the journal. Startup
//! copies each one into the journal database once and keeps the file as a
//! rollback artifact, so they are only ever a migration source.
//!
//! Opening one must never create it. `Connection::open` creates the file, so a
//! home with nothing to migrate would grow an empty store exactly where someone
//! debugging Broker state looks first, and a legacy store reached through a
//! link whose target is missing or temporarily unavailable would come back as
//! an empty file that every later start reads as "nothing to migrate".

use rusqlite::{Connection, OpenFlags};
use std::path::Path;

/// Opens the legacy `store` at `path` when there is one to migrate.
///
/// Only a missing directory entry inside a directory that exists means there
/// is nothing to migrate. `symlink_metadata` inspects the entry itself:
/// `exists` and `try_exists` follow symlinks, so a dangling link would read as
/// absent and the migration would be skipped, bringing the Broker up without
/// the state it was supposed to carry over. A missing parent is a mistyped
/// directory, not an empty home, and any other error (a permission problem, an
/// unreadable mount) means the Broker cannot tell, so both fail. An entry that
/// is present is opened without the create flag, so a dangling or
/// disappearing target fails instead of silently becoming an empty store.
///
/// `store` names the store in errors, as in "the legacy authority store".
pub(crate) fn open(path: &Path, store: &str) -> Result<Option<Connection>, String> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_URI,
        )
        .map(Some)
        .map_err(|error| {
            format!(
                "cannot open the legacy {store} store at {}: {error}",
                path.display()
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match std::fs::metadata(parent) {
                Ok(metadata) if metadata.is_dir() => Ok(None),
                Ok(_) => Err(format!(
                    "the legacy {store} store's directory {} is not a directory",
                    parent.display()
                )),
                Err(error) => Err(format!(
                    "cannot read the legacy {store} store's directory {}: {error}",
                    parent.display()
                )),
            }
        }
        Err(error) => Err(format!(
            "cannot tell whether the legacy {store} store at {} exists: {error}",
            path.display()
        )),
    }
}

/// A `file:` URI for attaching a legacy store read-write without creating it.
///
/// The migration attaches the store afresh on the journal connection, which
/// does create, so attaching the plain path would turn a store that vanished
/// since [`open`] into an empty file. SQLite decodes `%HH` in a URI path and
/// starts the query and fragment at `?` and `#`, so those three are escaped.
/// `path` is SQLite's own full pathname for the store (from
/// `pragma_database_list`), which never starts with `//` and so never reads
/// as a URI authority.
pub(crate) fn attach_uri(path: &str) -> String {
    let mut uri = String::from("file:");
    for character in path.chars() {
        match character {
            '%' => uri.push_str("%25"),
            '?' => uri.push_str("%3f"),
            '#' => uri.push_str("%23"),
            other => uri.push(other),
        }
    }
    uri.push_str("?mode=rw");
    uri
}

/// An audit signer for the migration unit tests in `authority` and `ceremony`,
/// which need a real journal to migrate into.
#[cfg(test)]
pub(crate) struct TestAuditSigner;

#[cfg(test)]
impl crate::journal::AuditSigner for TestAuditSigner {
    fn key_id(&self) -> bloom_broker_api::Token {
        bloom_broker_api::Token::new("broker-audit-test").unwrap()
    }

    fn sign(&self, message: &[u8]) -> Result<bloom_broker_api::Base64UrlBytes, String> {
        Ok(bloom_broker_api::Base64UrlBytes::from_bytes(message))
    }

    fn verify(
        &self,
        key_id: &bloom_broker_api::Token,
        message: &[u8],
        signature: &bloom_broker_api::Base64UrlBytes,
    ) -> Result<(), String> {
        (key_id == &self.key_id() && signature.decode() == message)
            .then_some(())
            .ok_or_else(|| "test audit signature mismatch".into())
    }
}
