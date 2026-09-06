//! Integration coverage for the frozen V1 relay wire contract.

use kynveil_protocol::{
    Accepted, Acknowledge, AuthorizeDeposit, CapabilityKind, Delivery, DeliveryPage, Deposit,
    DepositRecipient, ErrorCode, ErrorMessage, MailboxId, ObjectId, ProtocolError,
    ProvisionMailbox, Retrieve, RevokeDeposit, WireMessage, canonical_recipient_snapshot_digest,
    capability_verifier, decode, encode,
};

fn bytes<const LENGTH: usize>(value: u8) -> [u8; LENGTH] {
    [value; LENGTH]
}

#[test]
fn canonical_deposit_round_trip_preserves_the_immutable_snapshot() {
    let deposit = Deposit {
        object_id: ObjectId::new(bytes(0x10)),
        recipients: vec![
            DepositRecipient::new(MailboxId::new(bytes(0x20)), bytes(0x30)),
            DepositRecipient::new(MailboxId::new(bytes(0x21)), bytes(0x31)),
        ],
        ciphertext: vec![0x42],
        ttl_seconds: 604_800,
    };

    let encoded = encode(&WireMessage::Deposit(deposit.clone())).expect("deposit is valid");

    assert_eq!(decode(&encoded), Ok(WireMessage::Deposit(deposit)));
}

#[test]
fn rejects_noncanonical_duplicate_and_unknown_deposit_fields() {
    let canonical = encode(&WireMessage::Deposit(Deposit {
        object_id: ObjectId::new(bytes(0x10)),
        recipients: vec![DepositRecipient::new(
            MailboxId::new(bytes(0x20)),
            bytes(0x30),
        )],
        ciphertext: vec![0x42],
        ttl_seconds: 1,
    }))
    .expect("deposit is valid");

    let mut noncanonical = canonical.clone();
    noncanonical[2] = 0x18;
    noncanonical.insert(3, 1);
    assert_eq!(decode(&noncanonical), Err(ProtocolError::Malformed));

    let mut unknown = canonical;
    unknown[0] = 0xa9;
    unknown.extend([8, 0]);
    assert_eq!(decode(&unknown), Err(ProtocolError::Malformed));
}

#[test]
fn rejects_unsorted_or_duplicate_recipient_mailboxes() {
    let object_id = ObjectId::new(bytes(0x10));
    let later = MailboxId::new(bytes(0x21));
    let earlier = MailboxId::new(bytes(0x20));

    assert_eq!(
        encode(&WireMessage::Deposit(Deposit {
            object_id,
            recipients: vec![
                DepositRecipient::new(later, bytes(0x30)),
                DepositRecipient::new(earlier, bytes(0x31)),
            ],
            ciphertext: vec![0x42],
            ttl_seconds: 1,
        })),
        Err(ProtocolError::Malformed)
    );
}

#[test]
fn verifier_domains_are_permanent_and_separated() {
    let capability = bytes(0x55);

    assert_ne!(
        capability_verifier(CapabilityKind::Retrieve, &capability),
        capability_verifier(CapabilityKind::Management, &capability)
    );
    assert_ne!(
        capability_verifier(CapabilityKind::Management, &capability),
        capability_verifier(CapabilityKind::Deposit, &capability)
    );
}

#[test]
fn snapshot_digest_commits_to_mailboxes_and_deposit_verifiers() {
    let recipients = vec![
        DepositRecipient::new(MailboxId::new(bytes(0x20)), bytes(0x30)),
        DepositRecipient::new(MailboxId::new(bytes(0x21)), bytes(0x31)),
    ];
    let mut altered = recipients.clone();
    altered[1].deposit_capability[0] ^= 1;

    assert_ne!(
        canonical_recipient_snapshot_digest(&recipients).expect("ordered recipients are valid"),
        canonical_recipient_snapshot_digest(&altered).expect("ordered recipients are valid")
    );
}

#[test]
fn every_frozen_message_type_has_a_canonical_round_trip() {
    let mailbox_id = MailboxId::new(bytes(0x20));
    let object_id = ObjectId::new(bytes(0x10));
    let messages = vec![
        WireMessage::ProvisionMailbox(ProvisionMailbox {
            mailbox_id,
            retrieve_verifier: bytes(0x40),
            management_verifier: bytes(0x41),
        }),
        WireMessage::AuthorizeDeposit(AuthorizeDeposit {
            mailbox_id,
            management_capability: bytes(0x42),
            deposit_verifier: bytes(0x43),
        }),
        WireMessage::RevokeDeposit(RevokeDeposit {
            mailbox_id,
            management_capability: bytes(0x42),
            deposit_verifier: bytes(0x43),
        }),
        WireMessage::Retrieve(Retrieve {
            mailbox_id,
            retrieve_capability: bytes(0x44),
            after_sequence: 0,
        }),
        WireMessage::Acknowledge(Acknowledge {
            mailbox_id,
            object_id,
            delivery_sequence: 1,
            retrieve_capability: bytes(0x44),
        }),
        WireMessage::DeliveryPage(DeliveryPage {
            deliveries: vec![Delivery {
                delivery_sequence: 1,
                object_id,
                ciphertext: vec![0x45],
                expires_at_unix_seconds: 1,
            }],
            next_cursor: 1,
        }),
        WireMessage::Accepted(Accepted),
        WireMessage::Error(ErrorMessage {
            code: ErrorCode::UnauthorizedOrNotFound,
        }),
    ];

    for message in messages {
        let encoded = encode(&message).expect("message is valid");
        assert_eq!(decode(&encoded), Ok(message));
    }
}

#[test]
fn rejects_invalid_page_and_acknowledgement_bounds() {
    let mailbox_id = MailboxId::new(bytes(0x20));
    let object_id = ObjectId::new(bytes(0x10));

    assert_eq!(
        encode(&WireMessage::Acknowledge(Acknowledge {
            mailbox_id,
            object_id,
            delivery_sequence: 0,
            retrieve_capability: bytes(0x44),
        })),
        Err(ProtocolError::Malformed)
    );
    assert_eq!(
        encode(&WireMessage::DeliveryPage(DeliveryPage {
            deliveries: vec![
                Delivery {
                    delivery_sequence: 1,
                    object_id,
                    ciphertext: vec![0x45],
                    expires_at_unix_seconds: 1,
                };
                9
            ],
            next_cursor: 1,
        })),
        Err(ProtocolError::Malformed)
    );
}
