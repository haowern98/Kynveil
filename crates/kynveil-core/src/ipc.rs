//! Bounded framed IPC between Electron Main and the security core.

#[allow(missing_docs)]
#[allow(clippy::doc_markdown, clippy::trivially_copy_pass_by_ref)]
pub(crate) mod proto {
    include!(concat!(env!("OUT_DIR"), "/kynveil.ipc.v1.rs"));
}

use std::{
    io::{self, Read, Write},
    sync::{
        Mutex,
        mpsc::{TrySendError, sync_channel},
    },
    thread,
};

use prost::Message;

use self::proto::{
    CoreState, Envelope, ErrorCode, ErrorResponse, GetStatusResponse, HelloResponse,
    ShutdownResponse, envelope,
};

const PROTOCOL_MAJOR: u32 = 1;
const PROTOCOL_MINOR: u32 = 0;
const SESSION_ID_LENGTH: usize = 16;
const MAX_FRAME_LENGTH: usize = 1024 * 1024;
const MAX_QUEUED_REQUESTS: usize = 256;
const MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
enum FrameError {
    InvalidLength,
    FrameTooLarge,
    TruncatedPrefix,
    TruncatedBody,
    Io,
}

#[derive(Debug, PartialEq, Eq)]
enum ProtocolError {
    MalformedMessage,
}

#[derive(Debug, PartialEq, Eq)]
enum QueueError {
    Busy,
}

#[derive(Default)]
struct QueueBudget {
    requests: usize,
    bytes: usize,
}

struct QueuedRequest {
    bytes: usize,
    envelope: Envelope,
}

impl QueueBudget {
    fn reserve(&mut self, bytes: usize) -> Result<(), QueueError> {
        let Some(next_bytes) = self.bytes.checked_add(bytes) else {
            return Err(QueueError::Busy);
        };
        if self.requests == MAX_QUEUED_REQUESTS || next_bytes > MAX_QUEUED_BYTES {
            return Err(QueueError::Busy);
        }
        self.requests += 1;
        self.bytes = next_bytes;
        Ok(())
    }

    fn release(&mut self, bytes: usize) {
        self.requests -= 1;
        self.bytes -= bytes;
    }
}

struct Session {
    id: [u8; SESSION_ID_LENGTH],
    last_request_id: u64,
    handshaken: bool,
}

impl Session {
    fn new(id: [u8; SESSION_ID_LENGTH]) -> Self {
        Self {
            id,
            last_request_id: 0,
            handshaken: false,
        }
    }

    fn greeting(&self) -> Envelope {
        self.response(
            0,
            envelope::Body::HelloResponse(HelloResponse {
                core_build: env!("CARGO_PKG_VERSION").into(),
            }),
        )
    }

    fn handle(&mut self, request: Envelope) -> Envelope {
        let request_id = request.request_id;
        if request.protocol_major != PROTOCOL_MAJOR || request.protocol_minor != PROTOCOL_MINOR {
            return self.error(
                request_id,
                ErrorCode::UnsupportedVersion,
                "unsupported protocol",
            );
        }
        if request.session_id.as_slice() != self.id {
            return self.error(request_id, ErrorCode::StaleSession, "stale session");
        }
        if request_id == 0 || request_id <= self.last_request_id {
            return self.error(request_id, ErrorCode::DuplicateRequest, "duplicate request");
        }

        let Some(body) = request.body else {
            return self.error(request_id, ErrorCode::InvalidRequest, "invalid request");
        };

        let response = match body {
            envelope::Body::HelloRequest(hello) if !self.handshaken => {
                if hello.client_build.is_empty() || hello.client_build.len() > 128 {
                    return self.error(request_id, ErrorCode::InvalidRequest, "invalid request");
                }
                self.handshaken = true;
                envelope::Body::HelloResponse(HelloResponse {
                    core_build: env!("CARGO_PKG_VERSION").into(),
                })
            }
            envelope::Body::GetStatusRequest(_) if self.handshaken => {
                envelope::Body::GetStatusResponse(GetStatusResponse {
                    state: CoreState::Ready.into(),
                })
            }
            envelope::Body::ShutdownRequest(_) if self.handshaken => {
                envelope::Body::ShutdownResponse(ShutdownResponse {})
            }
            _ => return self.error(request_id, ErrorCode::InvalidRequest, "invalid request"),
        };

        self.last_request_id = request_id;
        self.response(request_id, response)
    }

    fn response(&self, request_id: u64, body: envelope::Body) -> Envelope {
        Envelope {
            protocol_major: PROTOCOL_MAJOR,
            protocol_minor: PROTOCOL_MINOR,
            session_id: self.id.to_vec(),
            request_id,
            body: Some(body),
        }
    }

    fn error(&self, request_id: u64, code: ErrorCode, message: &'static str) -> Envelope {
        self.response(
            request_id,
            envelope::Body::ErrorResponse(ErrorResponse {
                code: code.into(),
                message: message.into(),
            }),
        )
    }
}

fn read_frame(reader: &mut impl Read) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0_u8; 4];
    match reader.read(&mut prefix[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!(),
        Err(_) => return Err(FrameError::Io),
    }
    if reader.read_exact(&mut prefix[1..]).is_err() {
        return Err(FrameError::TruncatedPrefix);
    }

    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::InvalidLength);
    }
    if length > MAX_FRAME_LENGTH {
        return Err(FrameError::FrameTooLarge);
    }

    let mut body = vec![0; length];
    if reader.read_exact(&mut body).is_err() {
        return Err(FrameError::TruncatedBody);
    }
    Ok(Some(body))
}

fn write_frame(writer: &mut impl Write, envelope: &Envelope) -> io::Result<()> {
    let body = envelope.encode_to_vec();
    let length = u32::try_from(body.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "response frame too large"))?;
    writer.write_all(&length.to_be_bytes())?;
    writer.write_all(&body)?;
    writer.flush()
}

fn decode_envelope(body: &[u8]) -> Result<Envelope, ProtocolError> {
    Envelope::decode(body).map_err(|_| ProtocolError::MalformedMessage)
}

/// Runs the framed IPC service until stdin closes or a shutdown request succeeds.
pub(crate) fn run_stdio() -> Result<(), &'static str> {
    let mut session_id = [0_u8; SESSION_ID_LENGTH];
    getrandom::fill(&mut session_id).map_err(|_| "randomness unavailable")?;
    let session = Session::new(session_id);
    let mut input = io::stdin();
    let output = Mutex::new(io::stdout());
    let budget = Mutex::new(QueueBudget::default());
    let (sender, receiver) = sync_channel::<QueuedRequest>(MAX_QUEUED_REQUESTS);

    write_frame(
        &mut *output.lock().map_err(|_| "IPC output failed")?,
        &session.greeting(),
    )
    .map_err(|_| "IPC output failed")?;

    thread::scope(|scope| {
        let output_ref = &output;
        let budget_ref = &budget;
        let worker = scope.spawn(move || -> Result<(), &'static str> {
            let mut session = session;
            while let Ok(queued) = receiver.recv() {
                budget_ref
                    .lock()
                    .map_err(|_| "IPC queue failed")?
                    .release(queued.bytes);
                let response = session.handle(queued.envelope);
                let shutdown = matches!(response.body, Some(envelope::Body::ShutdownResponse(_)));
                write_frame(
                    &mut *output_ref.lock().map_err(|_| "IPC output failed")?,
                    &response,
                )
                .map_err(|_| "IPC output failed")?;
                if shutdown {
                    break;
                }
            }
            Ok(())
        });

        let reader_result = loop {
            let frame = match read_frame(&mut input) {
                Ok(Some(frame)) => frame,
                Ok(None) => break Ok(()),
                Err(_) => break Err("IPC framing failed"),
            };
            let Ok(envelope) = decode_envelope(&frame) else {
                break Err("IPC decoding failed");
            };
            let reserved = budget
                .lock()
                .map_err(|_| "IPC queue failed")?
                .reserve(frame.len())
                .is_ok();
            if !reserved {
                write_busy(&output, session_id, &envelope)?;
                continue;
            }
            match sender.try_send(QueuedRequest {
                bytes: frame.len(),
                envelope,
            }) {
                Ok(()) => {}
                Err(TrySendError::Full(queued)) => {
                    budget
                        .lock()
                        .map_err(|_| "IPC queue failed")?
                        .release(queued.bytes);
                    write_busy(&output, session_id, &queued.envelope)?;
                }
                Err(TrySendError::Disconnected(queued)) => {
                    budget
                        .lock()
                        .map_err(|_| "IPC queue failed")?
                        .release(queued.bytes);
                    break Ok(());
                }
            }
        };
        drop(sender);
        let worker_result = worker.join().map_err(|_| "IPC worker failed")?;
        reader_result.and(worker_result)
    })
}

fn write_busy(
    output: &Mutex<impl Write>,
    session_id: [u8; SESSION_ID_LENGTH],
    request: &Envelope,
) -> Result<(), &'static str> {
    let response = Envelope {
        protocol_major: PROTOCOL_MAJOR,
        protocol_minor: PROTOCOL_MINOR,
        session_id: session_id.to_vec(),
        request_id: request.request_id,
        body: Some(envelope::Body::ErrorResponse(ErrorResponse {
            code: ErrorCode::Busy.into(),
            message: "busy".into(),
        })),
    };
    write_frame(
        &mut *output.lock().map_err(|_| "IPC output failed")?,
        &response,
    )
    .map_err(|_| "IPC output failed")
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use prost::Message;

    use super::proto::{Envelope, GetStatusRequest, HelloRequest, envelope};
    use super::*;

    fn request(session_id: &[u8], request_id: u64, body: envelope::Body) -> Envelope {
        Envelope {
            protocol_major: 1,
            protocol_minor: 0,
            session_id: session_id.to_vec(),
            request_id,
            body: Some(body),
        }
    }

    fn framed(body: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(u32::try_from(body.len()).unwrap().to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    fn synthetic_session_id() -> [u8; SESSION_ID_LENGTH] {
        let mut session_id = [0; SESSION_ID_LENGTH];
        getrandom::fill(&mut session_id).unwrap();
        session_id
    }

    #[test]
    fn reads_fragmented_and_concatenated_frames() {
        let session_id = synthetic_session_id();
        let first = request(
            &session_id,
            1,
            envelope::Body::HelloRequest(HelloRequest {
                client_build: "synthetic-test-client".into(),
            }),
        )
        .encode_to_vec();
        let second = request(
            &session_id,
            2,
            envelope::Body::GetStatusRequest(GetStatusRequest {}),
        )
        .encode_to_vec();
        let bytes = [framed(&first), framed(&second)].concat();
        let mut reader = Cursor::new(bytes);

        assert_eq!(read_frame(&mut reader).unwrap(), Some(first));
        assert_eq!(read_frame(&mut reader).unwrap(), Some(second));
        assert_eq!(read_frame(&mut reader).unwrap(), None);
    }

    #[test]
    fn rejects_invalid_or_truncated_frames() {
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 0])),
            Err(FrameError::InvalidLength)
        );
        assert_eq!(
            read_frame(&mut Cursor::new(1_048_577_u32.to_be_bytes())),
            Err(FrameError::FrameTooLarge)
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0])),
            Err(FrameError::TruncatedPrefix)
        );
        assert_eq!(
            read_frame(&mut Cursor::new([0, 0, 0, 2, 1])),
            Err(FrameError::TruncatedBody)
        );
    }

    #[test]
    fn rejects_malformed_protobuf() {
        assert_eq!(
            decode_envelope(&[0x80]),
            Err(ProtocolError::MalformedMessage)
        );
    }

    #[test]
    fn validates_version_session_operation_and_request_identity() {
        let session_id = synthetic_session_id();
        let mut session = Session::new(session_id);

        let hello = request(
            &session_id,
            1,
            envelope::Body::HelloRequest(HelloRequest {
                client_build: "synthetic-test-client".into(),
            }),
        );
        assert!(matches!(
            session.handle(hello).body,
            Some(envelope::Body::HelloResponse(_))
        ));

        let duplicate = request(
            &session_id,
            1,
            envelope::Body::GetStatusRequest(GetStatusRequest {}),
        );
        assert_error(
            session.handle(duplicate),
            proto::ErrorCode::DuplicateRequest,
        );

        let mut stale_session_id = session_id;
        stale_session_id[0] ^= 1;
        let stale = request(
            &stale_session_id,
            2,
            envelope::Body::GetStatusRequest(GetStatusRequest {}),
        );
        assert_error(session.handle(stale), proto::ErrorCode::StaleSession);

        let mut unsupported = request(
            &session_id,
            2,
            envelope::Body::GetStatusRequest(GetStatusRequest {}),
        );
        unsupported.protocol_major = 2;
        assert_error(
            session.handle(unsupported),
            proto::ErrorCode::UnsupportedVersion,
        );

        let unknown = request(
            &session_id,
            2,
            envelope::Body::GetStatusRequest(GetStatusRequest {}),
        );
        let mut unknown = unknown;
        unknown.body = None;
        assert_error(session.handle(unknown), proto::ErrorCode::InvalidRequest);
    }

    #[test]
    fn enforces_both_queue_limits_and_drains() {
        let mut budget = QueueBudget::default();
        for _ in 0..MAX_QUEUED_REQUESTS {
            budget.reserve(1).unwrap();
        }
        assert_eq!(budget.reserve(1), Err(QueueError::Busy));
        budget.release(1);
        budget.reserve(1).unwrap();

        let mut byte_budget = QueueBudget::default();
        for _ in 0..16 {
            byte_budget.reserve(MAX_FRAME_LENGTH).unwrap();
        }
        assert_eq!(byte_budget.reserve(1), Err(QueueError::Busy));
        byte_budget.release(MAX_FRAME_LENGTH);
        byte_budget.reserve(1).unwrap();
    }

    fn assert_error(response: Envelope, expected: proto::ErrorCode) {
        let Some(envelope::Body::ErrorResponse(error)) = response.body else {
            panic!("expected error response");
        };
        assert_eq!(error.code, expected as i32);
    }
}
