/*
 * Copyright Stalwart Labs LLC See the COPYING
 * file at the top-level directory of this distribution.
 *
 * Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
 * https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
 * <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
 * option. This file may not be copied, modified, or distributed
 * except according to those terms.
 */

use std::{mem, pin::Pin, sync::Arc};

use ahash::AHashMap;
use futures_util::{
    stream::{SplitSink, SplitStream},
    SinkExt, Stream, StreamExt,
};
use parking_lot::Mutex;
use reqwest::header::SEC_WEBSOCKET_PROTOCOL;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    ClientConfig, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use tokio::{
    net::TcpStream,
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, Message},
    Connector, MaybeTlsStream, WebSocketStream,
};

use crate::{
    client::Client,
    core::{
        error::{ProblemDetails, ProblemType},
        request::{Arguments, Request},
        response::{Response, TaggedMethodResponse},
    },
    DataType, Method, PushObject, URI,
};

type PendingResponse = oneshot::Sender<crate::Result<Response<TaggedMethodResponse>>>;
type PendingResponses = Arc<Mutex<AHashMap<String, PendingResponse>>>;
const PUSH_CHANNEL_BUFFER: usize = 64;

#[derive(Debug, Serialize)]
struct WebSocketRequest {
    #[serde(rename = "@type")]
    pub _type: WebSocketRequestType,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    using: Vec<URI>,

    #[serde(rename = "methodCalls")]
    method_calls: Vec<(Method, Arguments, String)>,

    #[serde(rename = "createdIds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    created_ids: Option<AHashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct WebSocketResponse {
    #[serde(rename = "@type")]
    _type: WebSocketResponseType,

    #[serde(rename = "requestId")]
    request_id: Option<String>,

    #[serde(rename = "methodResponses")]
    method_responses: Vec<TaggedMethodResponse>,

    #[serde(rename = "createdIds")]
    created_ids: Option<AHashMap<String, String>>,

    #[serde(rename = "sessionState")]
    session_state: String,
}

#[derive(Debug, Serialize, Deserialize)]
enum WebSocketResponseType {
    Response,
}

#[derive(Debug, Serialize)]
struct WebSocketPushEnable {
    #[serde(rename = "@type")]
    _type: WebSocketPushEnableType,

    #[serde(rename = "dataTypes")]
    data_types: Option<Vec<DataType>>,

    #[serde(rename = "pushState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    push_state: Option<String>,
}

#[derive(Debug, Serialize)]
struct WebSocketPushDisable {
    #[serde(rename = "@type")]
    _type: WebSocketPushDisableType,
}

#[derive(Debug, Serialize)]
enum WebSocketRequestType {
    Request,
}

#[derive(Debug, Serialize)]
enum WebSocketPushEnableType {
    WebSocketPushEnable,
}

#[derive(Debug, Serialize)]
enum WebSocketPushDisableType {
    WebSocketPushDisable,
}

#[derive(Deserialize, Debug)]
pub struct WebSocketPushObject {
    #[serde(flatten)]
    pub push: PushObject,

    #[serde(rename = "pushState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub push_state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WebSocketError {
    #[serde(rename = "@type")]
    pub type_: WebSocketErrorType,

    #[serde(rename = "requestId")]
    pub request_id: Option<String>,

    #[serde(rename = "type")]
    p_type: ProblemType,
    status: Option<u32>,
    title: Option<String>,
    detail: Option<String>,
    limit: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub enum WebSocketErrorType {
    RequestError,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum WebSocketMessage_ {
    Response(WebSocketResponse),
    PushNotification(WebSocketPushObject),
    Error(WebSocketError),
}

#[derive(Debug)]
pub enum WebSocketMessage {
    Response(Response<TaggedMethodResponse>),
    PushNotification(PushObject),
}

pub struct WsStream {
    tx: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    req_id: u64,
}

struct CorrelatedWsTx {
    tx: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
    req_id: u64,
}

pub struct CorrelatedWs {
    client: Arc<Client>,
    tx: tokio::sync::Mutex<CorrelatedWsTx>,
    pending: PendingResponses,
    push_rx: tokio::sync::Mutex<mpsc::Receiver<crate::Result<PushObject>>>,
    shutdown: Mutex<Option<oneshot::Sender<()>>>,
}

#[doc(hidden)]
#[derive(Debug)]
struct DummyVerifier;

impl ServerCertVerifier for DummyVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls_pki_types::CertificateDer<'_>,
        _intermediates: &[rustls_pki_types::CertificateDer<'_>],
        _server_name: &rustls_pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls_pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls_pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

impl WsStream {
    fn new(tx: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>) -> Self {
        Self { tx, req_id: 0 }
    }

    fn next_request_id(&mut self) -> crate::Result<String> {
        next_request_id(&mut self.req_id, None)
    }
}

impl CorrelatedWsTx {
    fn new(tx: SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>) -> Self {
        Self { tx, req_id: 0 }
    }

    fn next_request_id(&mut self, pending: &PendingResponses) -> crate::Result<String> {
        next_request_id(&mut self.req_id, Some(pending))
    }
}

impl CorrelatedWs {
    pub async fn send(
        &self,
        request: Request<'_>,
    ) -> crate::Result<Response<TaggedMethodResponse>> {
        if !request.is_built_by(&self.client) {
            return Err(crate::Error::Internal(
                "Request was built by a different Client than this websocket connection."
                    .to_string(),
            ));
        }

        let (request_id, response) = {
            let mut tx = self.tx.lock().await;
            let request_id = tx.next_request_id(&self.pending)?;

            let (response_tx, response_rx) = oneshot::channel();
            self.pending.lock().insert(request_id.clone(), response_tx);

            if let Err(err) = tx
                .tx
                .send(serialize_ws_message(&WebSocketRequest {
                    _type: WebSocketRequestType::Request,
                    id: request_id.clone().into(),
                    using: request.using,
                    method_calls: request.method_calls,
                    created_ids: request.created_ids,
                })?)
                .await
            {
                self.pending.lock().remove(&request_id);
                return Err(err.into());
            }

            (request_id, response_rx)
        };

        match timeout(self.client.timeout(), response).await {
            Ok(Ok(response)) => {
                let response = response?;
                self.client.update_session_state(response.session_state());
                Ok(response)
            }
            Err(_) => {
                self.pending.lock().remove(&request_id);
                Err(crate::Error::Internal(format!(
                    "WebSocket response timed out after {:?}.",
                    self.client.timeout()
                )))
            }
            Ok(Err(_)) => {
                self.pending.lock().remove(&request_id);
                Err(crate::Error::Internal(
                    "WebSocket response channel closed.".to_string(),
                ))
            }
        }
    }

    pub async fn next_push(&self) -> Option<crate::Result<PushObject>> {
        self.push_rx.lock().await.recv().await
    }

    pub async fn enable_push_ws(
        &self,
        data_types: Option<impl IntoIterator<Item = DataType>>,
        push_state: Option<impl Into<String>>,
    ) -> crate::Result<()> {
        self.tx
            .lock()
            .await
            .tx
            .send(serialize_ws_message(&WebSocketPushEnable {
                _type: WebSocketPushEnableType::WebSocketPushEnable,
                data_types: data_types.map(|it| it.into_iter().collect()),
                push_state: push_state.map(|it| it.into()),
            })?)
            .await
            .map_err(|err| err.into())
    }

    pub async fn disable_push_ws(&self) -> crate::Result<()> {
        self.tx
            .lock()
            .await
            .tx
            .send(serialize_ws_message(&WebSocketPushDisable {
                _type: WebSocketPushDisableType::WebSocketPushDisable,
            })?)
            .await
            .map_err(|err| err.into())
    }

    pub async fn ws_ping(&self) -> crate::Result<()> {
        self.tx
            .lock()
            .await
            .tx
            .send(Message::Ping(vec![].into()))
            .await
            .map_err(|err| err.into())
    }
}

impl Drop for CorrelatedWs {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.lock().take() {
            let _ = shutdown.send(());
        }

        fail_pending_responses(&self.pending, "WebSocket connection dropped.".to_string());
    }
}

fn next_request_id(req_id: &mut u64, pending: Option<&PendingResponses>) -> crate::Result<String> {
    let request_id = *req_id;
    *req_id = req_id
        .checked_add(1)
        .ok_or_else(|| crate::Error::Internal("WebSocket request id overflow.".to_string()))?;

    let request_id = request_id.to_string();
    if matches!(pending, Some(pending) if pending.lock().contains_key(&request_id)) {
        return Err(crate::Error::Internal(format!(
            "WebSocket request id collision for requestId {request_id}."
        )));
    }

    Ok(request_id)
}

fn into_response(response: WebSocketResponse) -> Response<TaggedMethodResponse> {
    Response::new(
        response.method_responses,
        response.created_ids,
        response.session_state,
        response.request_id,
    )
}

fn parse_ws_message(message: Message) -> Option<crate::Result<WebSocketMessage_>> {
    if message.is_text() {
        Some(serde_json::from_slice::<WebSocketMessage_>(&message.into_data()).map_err(Into::into))
    } else {
        None
    }
}

fn serialize_ws_message(message: &impl Serialize) -> crate::Result<Message> {
    Ok(Message::text(serde_json::to_string(message)?))
}

fn resolve_ws_response(
    pending: &PendingResponses,
    response: WebSocketResponse,
) -> crate::Result<()> {
    let request_id = response.request_id.clone().ok_or_else(|| {
        crate::Error::Internal("WebSocket response missing requestId.".to_string())
    })?;

    if let Some(tx) = pending.lock().remove(&request_id) {
        let _ = tx.send(Ok(into_response(response)));
    }

    Ok(())
}

fn resolve_ws_error(pending: &PendingResponses, error: WebSocketError) -> crate::Result<()> {
    let request_id = error
        .request_id
        .clone()
        .ok_or_else(|| crate::Error::Internal("WebSocket error missing requestId.".to_string()))?;

    if let Some(tx) = pending.lock().remove(&request_id) {
        let _ = tx.send(Err(ProblemDetails::from(error).into()));
    }

    Ok(())
}

fn fail_pending_responses(pending: &PendingResponses, message: impl Into<String>) {
    let message = message.into();
    for (_, tx) in mem::take(&mut *pending.lock()) {
        let _ = tx.send(Err(crate::Error::Internal(message.clone())));
    }
}

impl Client {
    async fn open_ws(
        &self,
    ) -> crate::Result<(
        SplitSink<WebSocketStream<MaybeTlsStream<TcpStream>>, Message>,
        SplitStream<WebSocketStream<MaybeTlsStream<TcpStream>>>,
    )> {
        let session = self.session();
        let capabilities = session.websocket_capabilities().ok_or_else(|| {
            crate::Error::Internal(
                "JMAP server does not advertise any websocket capabilities.".to_string(),
            )
        })?;

        let mut request = capabilities.url().into_client_request()?;
        request
            .headers_mut()
            .insert("Authorization", self.authorization.parse().unwrap());
        request
            .headers_mut()
            .insert(SEC_WEBSOCKET_PROTOCOL, "jmap".parse().unwrap());

        let (stream, _) = if self.accept_invalid_certs & capabilities.url().starts_with("wss") {
            tokio_tungstenite::connect_async_tls_with_config(
                request,
                None,
                false,
                Connector::Rustls(Arc::new(
                    ClientConfig::builder()
                        .dangerous()
                        .with_custom_certificate_verifier(Arc::new(DummyVerifier {}))
                        .with_no_client_auth(),
                ))
                .into(),
            )
            .await?
        } else {
            tokio_tungstenite::connect_async(request).await?
        };

        Ok(stream.split())
    }

    pub async fn connect_ws(
        &self,
    ) -> crate::Result<Pin<Box<impl Stream<Item = crate::Result<WebSocketMessage>>>>> {
        let (tx, mut rx) = self.open_ws().await?;

        *self.ws.lock().await = Some(WsStream::new(tx));

        Ok(Box::pin(async_stream::stream! {
            while let Some(message) = rx.next().await {
                match message {
                    Ok(message) => {
                        if let Some(message) = parse_ws_message(message) {
                            match message {
                                Ok(WebSocketMessage_::Response(response)) => {
                                    yield Ok(WebSocketMessage::Response(into_response(response)))
                                }
                                Ok(WebSocketMessage_::PushNotification(push)) => {
                                    yield Ok(WebSocketMessage::PushNotification(push.push))
                                }
                                Ok(WebSocketMessage_::Error(err)) => {
                                    yield Err(ProblemDetails::from(err).into())
                                }
                                Err(err) => yield Err(err),
                            }
                        }
                    }
                    Err(err) => yield Err(err.into()),
                }
            }
        }))
    }

    pub async fn connect_ws_correlated(self: &Arc<Self>) -> crate::Result<CorrelatedWs> {
        let (tx, mut rx) = self.open_ws().await?;
        let pending = Arc::new(Mutex::new(AHashMap::new()));
        let (push_tx, push_rx) = mpsc::channel(PUSH_CHANNEL_BUFFER);
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
        let pending_ = pending.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => return,
                    message = rx.next() => match message {
                        Some(Ok(message)) => {
                            if let Some(message) = parse_ws_message(message) {
                                match message {
                                    Ok(WebSocketMessage_::Response(response)) => {
                                        if let Err(err) = resolve_ws_response(&pending_, response) {
                                            fail_pending_responses(&pending_, err.to_string());
                                            let _ = push_tx.send(Err(err)).await;
                                            return;
                                        }
                                    }
                                    Ok(WebSocketMessage_::PushNotification(push)) => {
                                        if push_tx.send(Ok(push.push)).await.is_err() {
                                            return;
                                        }
                                    }
                                    Ok(WebSocketMessage_::Error(err)) => {
                                        if let Err(err) = resolve_ws_error(&pending_, err) {
                                            fail_pending_responses(&pending_, err.to_string());
                                            let _ = push_tx.send(Err(err)).await;
                                            return;
                                        }
                                    }
                                    Err(err) => {
                                        fail_pending_responses(&pending_, err.to_string());
                                        let _ = push_tx.send(Err(err)).await;
                                        return;
                                    }
                                }
                            }
                        }
                        Some(Err(err)) => {
                            let err = crate::Error::from(err);
                            fail_pending_responses(&pending_, err.to_string());
                            let _ = push_tx.send(Err(err)).await;
                            return;
                        }
                        None => {
                            let message = "WebSocket stream closed.".to_string();
                            fail_pending_responses(&pending_, message.clone());
                            let _ = push_tx.send(Err(crate::Error::Internal(message))).await;
                            return;
                        }
                    },
                }
            }
        });

        Ok(CorrelatedWs {
            client: self.clone(),
            tx: tokio::sync::Mutex::new(CorrelatedWsTx::new(tx)),
            pending,
            push_rx: tokio::sync::Mutex::new(push_rx),
            shutdown: Mutex::new(Some(shutdown_tx)),
        })
    }

    pub async fn send_ws(&self, request: Request<'_>) -> crate::Result<String> {
        let mut _ws = self.ws.lock().await;
        let ws = _ws
            .as_mut()
            .ok_or_else(|| crate::Error::Internal("Websocket stream not set.".to_string()))?;

        let request_id = ws.next_request_id()?;

        ws.tx
            .send(serialize_ws_message(&WebSocketRequest {
                _type: WebSocketRequestType::Request,
                id: request_id.clone().into(),
                using: request.using,
                method_calls: request.method_calls,
                created_ids: request.created_ids,
            })?)
            .await?;

        Ok(request_id)
    }

    pub async fn enable_push_ws(
        &self,
        data_types: Option<impl IntoIterator<Item = DataType>>,
        push_state: Option<impl Into<String>>,
    ) -> crate::Result<()> {
        self.ws
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| crate::Error::Internal("Websocket stream not set.".to_string()))?
            .tx
            .send(serialize_ws_message(&WebSocketPushEnable {
                _type: WebSocketPushEnableType::WebSocketPushEnable,
                data_types: data_types.map(|it| it.into_iter().collect()),
                push_state: push_state.map(|it| it.into()),
            })?)
            .await
            .map_err(|err| err.into())
    }

    pub async fn disable_push_ws(&self) -> crate::Result<()> {
        self.ws
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| crate::Error::Internal("Websocket stream not set.".to_string()))?
            .tx
            .send(serialize_ws_message(&WebSocketPushDisable {
                _type: WebSocketPushDisableType::WebSocketPushDisable,
            })?)
            .await
            .map_err(|err| err.into())
    }

    pub async fn ws_ping(&self) -> crate::Result<()> {
        self.ws
            .lock()
            .await
            .as_mut()
            .ok_or_else(|| crate::Error::Internal("Websocket stream not set.".to_string()))?
            .tx
            .send(Message::Ping(vec![].into()))
            .await
            .map_err(|err| err.into())
    }
}

impl From<WebSocketError> for ProblemDetails {
    fn from(problem: WebSocketError) -> Self {
        ProblemDetails::new(
            problem.p_type,
            problem.status,
            problem.title,
            problem.detail,
            problem.limit,
            problem.request_id,
        )
    }
}

#[cfg(test)]
mod tests {
    use futures_util::FutureExt;

    use super::*;

    #[test]
    fn websocket_responses_are_correlated_by_request_id() {
        let pending = Arc::new(Mutex::new(AHashMap::new()));
        let (tx, rx) = oneshot::channel();
        pending.lock().insert("42".to_string(), tx);

        resolve_ws_response(
            &pending,
            WebSocketResponse {
                _type: WebSocketResponseType::Response,
                request_id: Some("42".to_string()),
                method_responses: vec![],
                created_ids: None,
                session_state: "state".to_string(),
            },
        )
        .unwrap();

        let response = rx.now_or_never().unwrap().unwrap().unwrap();
        assert_eq!(response.request_id(), Some("42"));
        assert_eq!(response.session_state(), "state");
    }

    #[test]
    fn websocket_errors_are_correlated_by_request_id() {
        let pending = Arc::new(Mutex::new(AHashMap::new()));
        let (tx, rx) = oneshot::channel();
        pending.lock().insert("7".to_string(), tx);

        resolve_ws_error(
            &pending,
            WebSocketError {
                type_: WebSocketErrorType::RequestError,
                request_id: Some("7".to_string()),
                p_type: ProblemType::Other("urn:test:error".to_string()),
                status: Some(400),
                title: Some("Bad request".to_string()),
                detail: None,
                limit: None,
            },
        )
        .unwrap();

        let error = rx.now_or_never().unwrap().unwrap().unwrap_err();
        match error {
            crate::Error::Problem(problem) => {
                assert_eq!(problem.request_id(), Some("7"));
                assert_eq!(problem.status(), Some(400));
            }
            err => panic!("unexpected error: {err:?}"),
        }
    }

    #[test]
    fn websocket_responses_without_request_id_fail_correlation() {
        let pending = Arc::new(Mutex::new(AHashMap::new()));

        let error = resolve_ws_response(
            &pending,
            WebSocketResponse {
                _type: WebSocketResponseType::Response,
                request_id: None,
                method_responses: vec![],
                created_ids: None,
                session_state: "state".to_string(),
            },
        )
        .unwrap_err();

        match error {
            crate::Error::Internal(message) => {
                assert!(message.contains("missing requestId"));
            }
            err => panic!("unexpected error: {err:?}"),
        }
    }

}
