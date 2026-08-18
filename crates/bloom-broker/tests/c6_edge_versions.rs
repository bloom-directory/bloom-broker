use std::{
    os::unix::fs::MetadataExt as _,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bloom_broker_api::{
    BROKER_API_CURRENT, BROKER_API_RANGE, BootEpoch, ProtocolVersion, ProtocolVersionRange, Token,
    WireErrorCode,
};
use bloom_triad_local_transport::{LocalIdentity, PeerAcl};
use ed25519_dalek::SigningKey;

struct EdgeResult {
    server: Result<(), bloom_broker_api::WireError>,
    client: Result<(), bloom_broker_api::WireError>,
    durable_work: usize,
}

async fn authenticate_edge(
    server_current: ProtocolVersion,
    server_range: ProtocolVersionRange,
    client_current: ProtocolVersion,
    client_range: ProtocolVersionRange,
    discriminator: u8,
) -> EdgeResult {
    let effective_uid = std::fs::metadata(".").unwrap().uid();
    let server_identity = identity("edge-server", discriminator, discriminator + 1);
    let client_identity = identity("edge-client", discriminator + 2, discriminator + 3);
    let server_acl = acl(effective_uid, &server_identity);
    let client_acl = acl(effective_uid, &client_identity);
    let durable_work = Arc::new(AtomicUsize::new(0));
    let (mut server_stream, mut client_stream) = tokio::net::UnixStream::pair().unwrap();

    let server = {
        let durable_work = durable_work.clone();
        tokio::spawn(async move {
            let result = bloom_triad_local_transport::authenticate_server(
                &mut server_stream,
                &server_identity,
                &client_acl,
                server_current,
                server_range,
            )
            .await;
            if result.is_ok() {
                durable_work.fetch_add(1, Ordering::SeqCst);
            }
            result
        })
    };
    let client = tokio::spawn(async move {
        bloom_triad_local_transport::authenticate_client(
            &mut client_stream,
            &client_identity,
            &server_acl,
            client_current,
            client_range,
        )
        .await
    });

    let (server, client) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        tokio::join!(server, client)
    })
    .await
    .expect("edge authentication must terminate");
    EdgeResult {
        server: server.unwrap(),
        client: client.unwrap(),
        durable_work: durable_work.load(Ordering::SeqCst),
    }
}

fn identity(service_id: &str, boot: u8, key: u8) -> LocalIdentity {
    LocalIdentity {
        service_id: Token::new(service_id).unwrap(),
        boot_epoch: BootEpoch::from_bytes([boot; 16]),
        application_key_id: Token::new(format!("{service_id}-key")).unwrap(),
        signing_key: Arc::new(SigningKey::from_bytes(&[key; 32])),
    }
}

fn acl(effective_uid: u32, identity: &LocalIdentity) -> PeerAcl {
    PeerAcl {
        effective_uid,
        service_id: identity.service_id.clone(),
        boot_epoch: identity.boot_epoch.clone(),
        application_key_id: identity.application_key_id.clone(),
        application_public_key: identity.signing_key.verifying_key().to_bytes(),
    }
}

fn downgrade_client_range() -> ProtocolVersionRange {
    // It accepts the server's 1.5 hello but advertises 1.0 as its current
    // request version, allowing the server-side authority range to reject it.
    ProtocolVersionRange::new(1, 0, 5)
}

#[tokio::test]
async fn machine_broker_downgrade_fails_before_durable_broker_work() {
    let result = authenticate_edge(
        BROKER_API_CURRENT,
        BROKER_API_RANGE,
        ProtocolVersion::new(1, 0),
        downgrade_client_range(),
        0x10,
    )
    .await;

    assert_eq!(
        result.server.unwrap_err().code,
        WireErrorCode::UnsupportedVersion
    );
    assert!(result.client.is_err());
    assert_eq!(result.durable_work, 0);
}

#[tokio::test]
async fn broker_signer_downgrade_fails_before_durable_broker_work() {
    let result = authenticate_edge(
        bloom_signer_api::SIGNER_API_CURRENT,
        bloom_signer_api::SIGNER_API_RANGE,
        ProtocolVersion::new(1, 0),
        downgrade_client_range(),
        0x20,
    )
    .await;

    assert_eq!(
        result.server.unwrap_err().code,
        WireErrorCode::UnsupportedVersion
    );
    assert!(result.client.is_err());
    assert_eq!(result.durable_work, 0);
}

#[tokio::test]
async fn authority_edges_negotiate_their_owner_ranges_independently() {
    let machine_broker = authenticate_edge(
        BROKER_API_CURRENT,
        BROKER_API_RANGE,
        BROKER_API_CURRENT,
        BROKER_API_RANGE,
        0x30,
    );
    let broker_signer = authenticate_edge(
        bloom_signer_api::SIGNER_API_CURRENT,
        bloom_signer_api::SIGNER_API_RANGE,
        ProtocolVersion::new(2, 1),
        ProtocolVersionRange::new(2, 1, 1),
        0x40,
    );
    let (machine_broker, broker_signer) = tokio::join!(machine_broker, broker_signer);

    assert!(machine_broker.server.is_ok());
    assert!(machine_broker.client.is_ok());
    assert_eq!(machine_broker.durable_work, 1);
    assert!(broker_signer.server.is_err());
    assert_eq!(
        broker_signer.client.unwrap_err().code,
        WireErrorCode::UnsupportedVersion
    );
    assert_eq!(broker_signer.durable_work, 0);
}
