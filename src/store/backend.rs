//! Per-request guest isolation with shared Rust socket and cookie transport.
use super::cancellation::Cancellation;
use super::runtime::{Request, Response, Runtime};
use crate::{client::AppleClient, error::ClientError, sap::ActionSigner};
use std::sync::Arc;

#[derive(Clone, Copy)]
pub(crate) enum ResponseFormat {
    Plist,
    Json,
    Raw,
}
#[derive(Clone, Copy)]
pub(crate) enum RedirectPolicy {
    Follow,
    Return,
}
#[derive(Clone, Copy)]
pub(crate) struct RequestOptions {
    pub format: ResponseFormat,
    pub redirects: RedirectPolicy,
    pub stream: bool,
}
impl RequestOptions {
    pub const PLIST: Self = Self {
        format: ResponseFormat::Plist,
        redirects: RedirectPolicy::Follow,
        stream: false,
    };
    pub const JSON: Self = Self {
        format: ResponseFormat::Json,
        ..Self::PLIST
    };
    pub const NO_REDIRECTS: Self = Self {
        redirects: RedirectPolicy::Return,
        ..Self::PLIST
    };
    pub const TRANSFER: Self = Self {
        format: ResponseFormat::Raw,
        stream: true,
        ..Self::PLIST
    };
}

async fn transport_response(
    client: reqwest::Client,
    request: reqwest::Request,
    stream: bool,
    cancellation: Cancellation,
    header_timeout: std::time::Duration,
) -> Result<Response, ClientError> {
    cancellation.check()?;
    // reqwest exposes a future up to response headers, not Go's separate
    // post-write header phase. This deadline also includes connect/upload.
    let mut response = tokio::select! {
        _=cancellation.cancelled()=>return Err(ClientError::Sap("Store request cancelled".into())),
        response=tokio::time::timeout(header_timeout,client.execute(request))=>response.map_err(|_|ClientError::StoreHeaderTimeout)??,
    };
    let status = response.status();
    let headers = response.headers().clone();
    if stream && ![301, 302, 303, 307, 308].contains(&status.as_u16()) {
        return Ok(Response {
            status,
            headers,
            body: Vec::new(),
            stream: Some(response),
        });
    }
    let mut body = Vec::new();
    loop {
        let chunk = tokio::select! {_=cancellation.cancelled()=>return Err(ClientError::Sap("Store request cancelled".into())),chunk=response.chunk()=>chunk?};
        let Some(chunk) = chunk else {
            break;
        };
        if body.len() + chunk.len() > 32 << 20 {
            return Err(ClientError::UnexpectedResponse(
                "Store API response exceeds size limit".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Response {
        status,
        headers,
        body,
        stream: None,
    })
}

impl AppleClient {
    pub(crate) async fn store_send(
        &self,
        operation: &str,
        mut request: reqwest::Request,
        parameters: Option<plist::Dictionary>,
        signer: Option<Arc<dyn ActionSigner>>,
        options: RequestOptions,
    ) -> Result<Response, ClientError> {
        let cancellation = Cancellation::new();
        let _guard = cancellation.guard();
        let image = self
            .store_image
            .get_or_try_init(|| async {
                let bundle = crate::sap::assets::macos27::load().await?;
                Ok::<_, ClientError>(Arc::new(bundle.apple_media_services))
            })
            .await?
            .clone();
        let stream = options.stream;
        let handle = tokio::runtime::Handle::current();
        let transport_client = if operation == "authenticate" {
            self.auth_http.clone()
        } else {
            self.protected_http().clone()
        };
        if !request.headers().contains_key(reqwest::header::USER_AGENT) {
            let agent = if operation == "purchase" {
                "Configurator/2.18 (Macintosh; OS X 15.3.2; 24D81) AppleWebKit/0620.2.4.11.6"
            } else {
                "Configurator/2.17 (Macintosh; OS X 15.2; 24C5089c) AppleWebKit/0620.1.16.11.6"
            };
            request
                .headers_mut()
                .insert(reqwest::header::USER_AGENT, agent.parse().unwrap());
        }
        let timeout = request.timeout().copied();
        let transport_cancellation = cancellation.clone();
        let transport = Arc::new(move |mut request: reqwest::Request| {
            let client = transport_client.clone();
            *request.timeout_mut() = timeout;
            handle.block_on(transport_response(
                client,
                request,
                stream,
                transport_cancellation.clone(),
                std::time::Duration::from_secs(30),
            ))
        });
        let body = request
            .body()
            .map(|body| {
                body.as_bytes().map(Vec::from).ok_or_else(|| {
                    ClientError::UnexpectedResponse(
                        "Store API request must have a buffered body".into(),
                    )
                })
            })
            .transpose()?
            .unwrap_or_default();
        if body.len() > 1 << 20 {
            return Err(ClientError::UnexpectedResponse(
                "Store request body exceeds size limit".into(),
            ));
        }
        let input = Request {
            url: request.url().clone(),
            method: request.method().clone(),
            operation: operation.into(),
            format: match options.format {
                ResponseFormat::Json => "json",
                ResponseFormat::Plist => "plist",
                ResponseFormat::Raw => "",
            },
            headers: request.headers().clone(),
            parameters,
            body,
            bag: self
                .store_bag
                .lock()
                .map_err(|_| ClientError::Sap("Store bag lock poisoned".into()))?
                .clone(),
            hardware_id: self.hardware_id().to_vec(),
            signer,
            transport,
            stream,
            raw: matches!(options.format, ResponseFormat::Raw),
            no_redirects: matches!(options.redirects, RedirectPolicy::Return),
        };
        let machine = crate::guid::MachineIdentity {
            guid: self.guid().into(),
            hardware_id: self.hardware_id().to_vec(),
        };
        let cache = self.cache_dir().to_owned();
        let worker_handle = tokio::runtime::Handle::current();
        // Construct and destroy Unicorn on this worker, avoiding a Send assertion
        // on its raw engine pointers or on the generic emulator hook API.
        let mut response = tokio::task::spawn_blocking(move || {
            cancellation.check()?;
            let client = AppleClient::new(machine, None, cache)?;
            let mut runtime =
                worker_handle.block_on(Runtime::open_cancellable(&client, &image, cancellation))?;
            runtime.execute(input)
        })
        .await
        .map_err(|_| ClientError::Sap("Store framework worker failed".into()))??;
        if !stream
            && response
                .headers
                .get(reqwest::header::CONTENT_ENCODING)
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case("gzip"))
        {
            use std::io::Read;
            let mut body = Vec::new();
            flate2::read::GzDecoder::new(response.body.as_slice())
                .take((32 << 20) + 1)
                .read_to_end(&mut body)
                .map_err(|_| {
                    ClientError::UnexpectedResponse("invalid compressed Store response".into())
                })?;
            if body.len() > 32 << 20 {
                return Err(ClientError::UnexpectedResponse(
                    "Store response exceeds size limit".into(),
                ));
            }
            response.body = body;
            response.headers.remove(reqwest::header::CONTENT_LENGTH);
            response.headers.remove(reqwest::header::CONTENT_ENCODING);
        }
        if operation == "bag"
            && response.status.is_success()
            && let Ok(values) =
                crate::client::plist_xml::parse_plist_response::<plist::Dictionary>(&response.body)
        {
            *self
                .store_bag
                .lock()
                .map_err(|_| ClientError::Sap("Store bag lock poisoned".into()))? = Some(values);
        }
        Ok(response)
    }
}

impl Response {
    pub fn status(&self) -> reqwest::StatusCode {
        self.status
    }
    pub fn headers(&self) -> &reqwest::header::HeaderMap {
        &self.headers
    }
    pub async fn bytes(self) -> Result<bytes::Bytes, ClientError> {
        Ok(self.body.into())
    }
    pub async fn text(self) -> Result<String, ClientError> {
        String::from_utf8(self.body)
            .map_err(|_| ClientError::UnexpectedResponse("invalid UTF-8 Store response".into()))
    }
    pub fn error_for_status(self) -> Result<Self, ClientError> {
        if self.status.is_client_error() || self.status.is_server_error() {
            Err(ClientError::UnexpectedResponse(format!(
                "Store request failed with HTTP {}",
                self.status
            )))
        } else {
            Ok(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "reads the live public Apple bag and catalog; no saved account or authentication"]
    async fn live_store_backend_public_bag_and_catalog() {
        let client = AppleClient::for_tests();
        let bag = crate::api::bag::fetch_bag(&client).await.unwrap();
        assert_eq!(bag.sap.version, 200);
        assert!(client.store_bag.lock().unwrap().is_some());
        let image = client.store_image.get().unwrap().clone();
        let app = crate::api::lookup::lookup(
            &client,
            "com.spotify.client",
            "us",
            crate::model::Platform::IPhone,
        )
        .await
        .unwrap();
        assert!(app.is_some());
        assert!(Arc::ptr_eq(&image, client.store_image.get().unwrap()));
    }

    #[tokio::test]
    async fn stalled_headers_time_out_and_cancellation_interrupts_transport() {
        use std::io::{Read, Write};
        for (cancel, partial_body) in [(false, false), (true, false), (true, true)] {
            let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let address = server.local_addr().unwrap();
            let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
            let (release_tx, release_rx) = std::sync::mpsc::channel();
            let thread = std::thread::spawn(move || {
                let (mut connection, _) = server.accept().unwrap();
                connection
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let mut request = Vec::new();
                let mut byte = [0; 1];
                while !request.ends_with(b"\r\n\r\n") {
                    connection.read_exact(&mut byte).unwrap();
                    request.push(byte[0]);
                }
                if partial_body {
                    connection
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\npart")
                        .unwrap();
                }
                let _ = ready_tx.send(());
                let _ = release_rx.recv_timeout(std::time::Duration::from_secs(2));
            });
            let token = Cancellation::new();
            let worker_token = token.clone();
            let client = reqwest::Client::new();
            let request = client
                .get(format!("http://{address}/stalled"))
                .build()
                .unwrap();
            let timeout = if cancel {
                std::time::Duration::from_secs(30)
            } else {
                std::time::Duration::from_millis(100)
            };
            let worker = tokio::spawn(transport_response(
                client,
                request,
                false,
                worker_token,
                timeout,
            ));
            ready_rx.await.unwrap();
            if cancel {
                token.cancel();
            }
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), worker)
                .await
                .unwrap()
                .unwrap();
            if cancel {
                assert!(
                    matches!(result,Err(ClientError::Sap(message))if message.contains("cancelled"))
                );
            } else {
                assert!(matches!(result, Err(ClientError::StoreHeaderTimeout)));
            }
            let _ = release_tx.send(());
            thread.join().unwrap();
        }
    }
    #[tokio::test]
    #[ignore = "requires pinned Apple assets and ARM64 Unicorn; server is local and credentials are synthetic"]
    async fn live_store_backend_preserves_streamed_range() {
        use std::io::{Read, Write};
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let thread = std::thread::spawn(move || {
            let (mut connection, _) = server.accept().unwrap();
            connection
                .set_read_timeout(Some(std::time::Duration::from_secs(30)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0; 1];
            while !request.ends_with(b"\r\n\r\n") {
                connection.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() < 16384);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.contains("range: bytes=3-\r\n"));
            connection.write_all(b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 3-6/7\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\na\0\xffb").unwrap();
        });
        let client = AppleClient::for_tests();
        let request = client
            .http()
            .get(format!("http://{address}/package"))
            .header("Range", "bytes=3-")
            .build()
            .unwrap();
        let response = client
            .store_send("transfer", request, None, None, RequestOptions::TRANSFER)
            .await
            .unwrap();
        assert_eq!(response.status, reqwest::StatusCode::PARTIAL_CONTENT);
        assert_eq!(
            response.headers[reqwest::header::CONTENT_RANGE],
            "bytes 3-6/7"
        );
        let stream = response.stream.unwrap();
        assert_eq!(stream.content_length(), Some(4));
        assert_eq!(stream.bytes().await.unwrap().as_ref(), b"a\0\xffb");
        thread.join().unwrap();
    }
}
