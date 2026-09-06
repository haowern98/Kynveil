//! Black-box coverage for the Stage 4 blind relay state machine.

use kynveil_protocol::{
    Accepted, Acknowledge, AuthorizeDeposit, CapabilityKind, DeliveryPage, Deposit,
    DepositRecipient, ErrorCode, ErrorMessage, MailboxId, ObjectId, ProvisionMailbox, Retrieve,
    RevokeDeposit, WireMessage, capability_verifier,
};
use kynveil_relay::Relay;
use std::{env, fs, process};

fn bytes<const LENGTH: usize>(value: u8) -> [u8; LENGTH] {
    [value; LENGTH]
}

fn mailbox(value: u8) -> MailboxId {
    MailboxId::new(bytes(value))
}

#[allow(clippy::needless_pass_by_value)]
fn response(relay: &mut Relay, request: WireMessage, now: u64) -> WireMessage {
    relay
        .handle(&request, now)
        .expect("relay storage is available")
}

fn accepted(relay: &mut Relay, request: WireMessage, now: u64) {
    assert_eq!(
        response(relay, request, now),
        WireMessage::Accepted(Accepted)
    );
}

fn provision_and_authorize(relay: &mut Relay, mailbox_id: MailboxId, cap: [u8; 32], now: u64) {
    let retrieve = bytes(0x80_u8.wrapping_add(mailbox_id.as_bytes()[0]));
    let management = bytes(0x90_u8.wrapping_add(mailbox_id.as_bytes()[0]));
    accepted(
        relay,
        WireMessage::ProvisionMailbox(ProvisionMailbox {
            mailbox_id,
            retrieve_verifier: capability_verifier(CapabilityKind::Retrieve, &retrieve),
            management_verifier: capability_verifier(CapabilityKind::Management, &management),
        }),
        now,
    );
    accepted(
        relay,
        WireMessage::AuthorizeDeposit(AuthorizeDeposit {
            mailbox_id,
            management_capability: management,
            deposit_verifier: capability_verifier(CapabilityKind::Deposit, &cap),
        }),
        now,
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn deposit_retrieval_and_recipient_specific_acknowledgement_are_transactional() {
    let mut relay = Relay::open_in_memory().expect("in-memory SQLite relay opens");
    let first = mailbox(0x20);
    let second = mailbox(0x21);
    let first_cap = bytes(0x30);
    let second_cap = bytes(0x31);
    provision_and_authorize(&mut relay, first, first_cap, 10);
    provision_and_authorize(&mut relay, second, second_cap, 10);

    let deposit = Deposit {
        object_id: ObjectId::new(bytes(0x10)),
        recipients: vec![
            DepositRecipient::new(first, first_cap),
            DepositRecipient::new(second, second_cap),
        ],
        ciphertext: vec![0x44, 0x55],
        ttl_seconds: 60,
    };
    accepted(&mut relay, WireMessage::Deposit(deposit.clone()), 10);

    let first_retrieve = bytes(0xa0);
    let first_page = response(
        &mut relay,
        WireMessage::Retrieve(Retrieve {
            mailbox_id: first,
            retrieve_capability: first_retrieve,
            after_sequence: 0,
        }),
        10,
    );
    let expected_first_page = WireMessage::DeliveryPage(DeliveryPage {
        deliveries: vec![kynveil_protocol::Delivery {
            delivery_sequence: 1,
            object_id: deposit.object_id,
            ciphertext: deposit.ciphertext.clone(),
            expires_at_unix_seconds: 70,
        }],
        next_cursor: 1,
    });
    assert_eq!(first_page, expected_first_page);
    assert_eq!(
        response(
            &mut relay,
            WireMessage::Retrieve(Retrieve {
                mailbox_id: first,
                retrieve_capability: first_retrieve,
                after_sequence: 0,
            }),
            10,
        ),
        expected_first_page
    );

    accepted(
        &mut relay,
        WireMessage::Acknowledge(Acknowledge {
            mailbox_id: first,
            object_id: deposit.object_id,
            delivery_sequence: 1,
            retrieve_capability: first_retrieve,
        }),
        10,
    );
    assert_eq!(
        response(
            &mut relay,
            WireMessage::Retrieve(Retrieve {
                mailbox_id: first,
                retrieve_capability: first_retrieve,
                after_sequence: 0,
            }),
            10,
        ),
        WireMessage::DeliveryPage(DeliveryPage {
            deliveries: Vec::new(),
            next_cursor: 0,
        })
    );

    let second_retrieve = bytes(0xa1);
    assert!(matches!(
        response(
            &mut relay,
            WireMessage::Retrieve(Retrieve {
                mailbox_id: second,
                retrieve_capability: second_retrieve,
                after_sequence: 0,
            }),
            10,
        ),
        WireMessage::DeliveryPage(DeliveryPage { deliveries, .. }) if deliveries.len() == 1
    ));
    accepted(
        &mut relay,
        WireMessage::Acknowledge(Acknowledge {
            mailbox_id: second,
            object_id: deposit.object_id,
            delivery_sequence: 1,
            retrieve_capability: second_retrieve,
        }),
        10,
    );
    accepted(&mut relay, WireMessage::Deposit(deposit.clone()), 10);

    let mut changed = deposit;
    changed.ciphertext.push(0x66);
    assert_eq!(
        response(&mut relay, WireMessage::Deposit(changed), 10),
        WireMessage::Error(ErrorMessage {
            code: ErrorCode::BadRequest,
        })
    );
}

#[test]
fn revoked_grants_block_new_objects_but_not_exact_retries() {
    let mut relay = Relay::open_in_memory().expect("in-memory SQLite relay opens");
    let mailbox_id = mailbox(0x20);
    let deposit_capability = bytes(0x30);
    provision_and_authorize(&mut relay, mailbox_id, deposit_capability, 10);
    let deposit = Deposit {
        object_id: ObjectId::new(bytes(0x10)),
        recipients: vec![DepositRecipient::new(mailbox_id, deposit_capability)],
        ciphertext: vec![0x44],
        ttl_seconds: 60,
    };
    accepted(&mut relay, WireMessage::Deposit(deposit.clone()), 10);

    accepted(
        &mut relay,
        WireMessage::RevokeDeposit(RevokeDeposit {
            mailbox_id,
            management_capability: bytes(0xb0),
            deposit_verifier: capability_verifier(CapabilityKind::Deposit, &deposit_capability),
        }),
        10,
    );
    accepted(&mut relay, WireMessage::Deposit(deposit), 10);
    assert_eq!(
        response(
            &mut relay,
            WireMessage::Deposit(Deposit {
                object_id: ObjectId::new(bytes(0x11)),
                recipients: vec![DepositRecipient::new(mailbox_id, deposit_capability)],
                ciphertext: vec![0x44],
                ttl_seconds: 60,
            }),
            10,
        ),
        WireMessage::Error(ErrorMessage {
            code: ErrorCode::UnauthorizedOrNotFound,
        })
    );
}

#[test]
fn restart_preserves_expiry_tombstones_without_persisting_raw_capabilities() {
    let path = env::temp_dir().join(format!("kynveil-relay-{}.db", process::id()));
    let _ = fs::remove_file(&path);
    let mailbox_id = mailbox(0x20);
    let deposit_capability = bytes(0x30);
    let deposit = Deposit {
        object_id: ObjectId::new(bytes(0x10)),
        recipients: vec![DepositRecipient::new(mailbox_id, deposit_capability)],
        ciphertext: vec![0x44],
        ttl_seconds: 1,
    };

    {
        let mut relay = Relay::open(&path).expect("durable SQLite relay opens");
        provision_and_authorize(&mut relay, mailbox_id, deposit_capability, 10);
        accepted(&mut relay, WireMessage::Deposit(deposit.clone()), 10);
    }
    let mut relay = Relay::open(&path).expect("relay reopens after restart");
    assert!(matches!(
        response(
            &mut relay,
            WireMessage::Retrieve(Retrieve {
                mailbox_id,
                retrieve_capability: bytes(0xa0),
                after_sequence: 0,
            }),
            10,
        ),
        WireMessage::DeliveryPage(DeliveryPage { deliveries, .. }) if deliveries.len() == 1
    ));
    accepted(&mut relay, WireMessage::Deposit(deposit), 11);
    assert!(
        !fs::read(&path)
            .expect("relay database is readable as bytes")
            .windows(deposit_capability.len())
            .any(|window| window == deposit_capability)
    );
}
