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
            unreachable_store(
                store,
                "open_failed",
                None,
                format!(
                    "cannot open the legacy {store} store at {}: {error}",
                    path.display()
                ),
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let parent = path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."));
            match std::fs::metadata(parent) {
                Ok(metadata) if metadata.is_dir() => Ok(None),
                Ok(_) => Err(unreachable_store(
                    store,
                    "directory_not_a_directory",
                    None,
                    format!(
                        "the legacy {store} store's directory {} is not a directory",
                        parent.display()
                    ),
                )),
                Err(error) => Err(unreachable_store(
                    store,
                    "directory_unreadable",
                    Some(error.kind()),
                    format!(
                        "cannot read the legacy {store} store's directory {}: {error}",
                        parent.display()
                    ),
                )),
            }
        }
        Err(error) => Err(unreachable_store(
            store,
            "entry_uninspectable",
            Some(error.kind()),
            format!(
                "cannot tell whether the legacy {store} store at {} exists: {error}",
                path.display()
            ),
        )),
    }
}

/// Whether the legacy store holds `name`, found the way a query would find it:
/// SQLite resolves table names without regard to ASCII case, and a view of
/// that name reads like the table.
pub(crate) fn has_table(connection: &Connection, name: &str) -> rusqlite::Result<bool> {
    connection.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master
         WHERE type IN ('table', 'view') AND name = ?1 COLLATE NOCASE)",
        [name],
        |row| row.get(0),
    )
}

/// Attaches the legacy `store` to the journal connection `target` as `schema`,
/// read-write and never created.
///
/// `path` is SQLite's own full pathname for the store, from
/// `pragma_database_list`. The journal connection creates missing databases,
/// so attaching the plain path would turn a store that vanished since [`open`]
/// into an empty file that every later start reads as nothing to migrate.
pub(crate) fn attach(
    target: &Connection,
    path: &str,
    schema: &'static str,
    store: &str,
) -> Result<(), String> {
    target
        .execute(
            &format!("ATTACH DATABASE ?1 AS {schema}"),
            [attach_uri(path)],
        )
        .map(|_| ())
        .map_err(|error| {
            unreachable_store(
                store,
                "attach_failed",
                None,
                format!("cannot attach the legacy {store} store at {path}: {error}"),
            )
        })
}

/// A `file:` URI that opens `path` read-write but never creates it. SQLite
/// decodes `%HH` in a URI path and starts the query and fragment at `?` and
/// `#`, so those three are escaped. `path` is SQLite's own full pathname,
/// which never starts with `//` and so never reads as a URI authority.
fn attach_uri(path: &str) -> String {
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

/// Records why a legacy store stopped startup, and returns the error.
///
/// The Broker never logs a run error's text, because it can carry secrets, so
/// without this an operator sees only that the Broker exited. The event names
/// the store and the reason, never the path or the underlying message.
fn unreachable_store(
    store: &str,
    reason: &'static str,
    io_error: Option<std::io::ErrorKind>,
    message: String,
) -> String {
    tracing::error!(
        event = "storage.legacy_store_unreachable",
        store,
        reason,
        io_error = io_error.map(|kind| kind.to_string()),
        "a legacy store could not be read, so startup stops instead of skipping its migration"
    );
    message
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

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::prelude::*;

    /// The check must find the table wherever the migration's own
    /// `SELECT * FROM <name>` would, or a store it could read is skipped.
    #[test]
    fn has_table_finds_what_a_query_would_find() {
        let connection = Connection::open_in_memory().unwrap();
        assert!(!has_table(&connection, "ceremony_sessions").unwrap());

        connection
            .execute_batch(
                "CREATE TABLE Ceremony_Sessions(id TEXT);
                 CREATE TABLE stored(id TEXT);
                 CREATE VIEW policies AS SELECT * FROM stored;
                 CREATE INDEX wallet_epochs ON stored(id);",
            )
            .unwrap();
        assert!(
            has_table(&connection, "ceremony_sessions").unwrap(),
            "SQLite resolves table names without regard to case"
        );
        assert!(
            has_table(&connection, "policies").unwrap(),
            "a view reads like the table"
        );
        assert!(
            !has_table(&connection, "wallet_epochs").unwrap(),
            "an index is not something a query can select from"
        );
    }

    /// The Broker never logs a run error's text, so a store that stops
    /// startup must say so itself, and without the path, which is the
    /// operator's configuration rather than something to write to the log.
    #[cfg(unix)]
    #[test]
    fn an_unreachable_store_is_logged_by_store_and_reason_only() {
        let directory = tempfile::tempdir().unwrap();
        let volume = directory.path().join("mounted-volume");
        std::fs::create_dir(&volume).unwrap();
        let path = directory.path().join("ceremonies.sqlite");
        std::os::unix::fs::symlink(volume.join("ceremonies.sqlite"), &path).unwrap();

        let capture = bloom_service_observability::CapturedWriter::default();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_writer(capture.clone()),
        );
        let error = tracing::subscriber::with_default(subscriber, || {
            open(&path, "ceremony").expect_err("a dangling store must not open")
        });

        let logged = capture.text();
        assert!(
            logged.contains("storage.legacy_store_unreachable"),
            "{logged}"
        );
        assert!(logged.contains("\"store\":\"ceremony\""), "{logged}");
        assert!(logged.contains("\"reason\":\"open_failed\""), "{logged}");
        assert!(
            !logged.contains(directory.path().to_str().unwrap()),
            "the event must not carry the path: {logged}"
        );
        assert!(error.contains("ceremonies.sqlite"), "{error}");
    }
}
