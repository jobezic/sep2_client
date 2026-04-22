use std::{
    future::Future,
    net::{self, SocketAddr},
    path::Path,
    sync::Arc,
};

use anyhow::{anyhow, Result};
use hyper::{
    header::LOCATION, server::conn::Http, service::service_fn, Body, Method, Request, Response,
    StatusCode,
};
use rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
use rustls::{
    server::{AllowAnyAuthenticatedClient, ServerConfig}, version, Certificate, PrivateKey,
    RootCertStore, SupportedCipherSuite, ALL_KX_GROUPS,
};
use rustls_pemfile::Item;

use sep2_common::examples::{
    DC_16_04_11, EDL_16_02_08, ED_16_01_08, ED_16_03_06, ER_16_04_06, FSAL_16_03_11, REG_16_01_10,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

type TlsServerConfig = Arc<ServerConfig>;

const TLS12_ECDHE_ECDSA_AES128_GCM_SHA256: &[SupportedCipherSuite] =
    &[TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256];

fn create_server_tls_config(
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
    rootca_path: impl AsRef<Path>,
) -> Result<TlsServerConfig> {
    let root_store = load_root_cert_store(rootca_path)?;
    let verifier = AllowAnyAuthenticatedClient::new(root_store);
    let cert_chain = load_certificates(cert_path)?;
    let private_key = load_private_key(pk_path)?;
    let config = ServerConfig::builder()
        .with_cipher_suites(TLS12_ECDHE_ECDSA_AES128_GCM_SHA256)
        .with_kx_groups(&ALL_KX_GROUPS)
        .with_protocol_versions(&[&version::TLS12])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, private_key)?;
    Ok(Arc::new(config))
}

pub struct TestServer {
    addr: SocketAddr,
    cfg: TlsServerConfig,
}

impl TestServer {
    pub fn new(
        addr: impl net::ToSocketAddrs,
        cert_path: impl AsRef<Path>,
        pk_path: impl AsRef<Path>,
        rootca_path: impl AsRef<Path>,
    ) -> Result<Self> {
        let cfg = create_server_tls_config(cert_path, pk_path, rootca_path)?;
        Ok(TestServer {
            addr: addr
                .to_socket_addrs()?
                .next()
                .ok_or(anyhow!("Given server address did not yield a SocketAddr"))?,
            cfg,
        })
    }

    pub async fn run(self, shutdown: impl Future) -> Result<()> {
        tokio::pin!(shutdown);
        let acceptor = TlsAcceptor::from(self.cfg);
        let listener = TcpListener::bind(self.addr).await?;
        let mut set = tokio::task::JoinSet::new();
        log::info!("TestServer: Listening on {}", self.addr);
        loop {
            // Accept TCP Connection
            let (stream, addr) = tokio::select! {
                _ = &mut shutdown => break,
                res = listener.accept() => match res {
                    Ok((s,a)) => (s,a),
                    Err(err) => {
                        log::error!("TestServer: Failed to accept connection: {err}");
                        continue;
                    }
                }
            };
            log::debug!("TestServer: Remote connecting from {}", addr);

            // Perform TLS handshake
            let stream = match acceptor.accept(stream).await {
                Ok(stream) => stream,
                Err(e) => {
                    log::error!("TestServer: Failed to perform TLS handshake: {e}");
                    continue;
                }
            };

            // Bind connection to service
            let service = service_fn(move |req| async move { router(req).await });
            set.spawn(async move {
                if let Err(err) = Http::new().serve_connection(stream, service).await {
                    log::error!("TestServer: Failed to handle connection: {err}");
                }
            });
        }
        // Wait for all connection handlers to finish
        log::debug!("TestServer: Attempting graceful shutdown");
        set.shutdown().await;
        log::info!("TestServer: Server has been shutdown.");
        Ok(())
    }
}

fn load_root_cert_store(rootca_path: impl AsRef<Path>) -> Result<RootCertStore> {
    let path = rootca_path.as_ref();
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path.display())
    }

    let mut root_store = RootCertStore::empty();
    let (added, _ignored) = root_store.add_parsable_certificates(&certs);
    if added == 0 {
        anyhow::bail!("Failed to parse any root certificates from {}", path.display())
    }
    Ok(root_store)
}

fn load_certificates(cert_path: impl AsRef<Path>) -> Result<Vec<Certificate>> {
    let path = cert_path.as_ref();
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    if certs.is_empty() {
        anyhow::bail!("No certificates found in {}", path.display())
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn load_private_key(pk_path: impl AsRef<Path>) -> Result<PrivateKey> {
    let path = pk_path.as_ref();
    let file = std::fs::File::open(path)?;
    let mut reader = std::io::BufReader::new(file);

    for item in rustls_pemfile::read_all(&mut reader)? {
        match item {
            Item::PKCS8Key(key) | Item::RSAKey(key) | Item::ECKey(key) => {
                return Ok(PrivateKey(key));
            }
            _ => continue,
        }
    }

    anyhow::bail!("No private key found in {}", path.display())
}

async fn router(req: Request<Body>) -> Result<Response<Body>> {
    log::info!("Incoming Request: {:?}", req);
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/dcap") => {
            *response.body_mut() = Body::from(DC_16_04_11);
        }
        (&Method::GET, "/edev") => {
            *response.body_mut() = Body::from(EDL_16_02_08);
        }
        (&Method::POST, "/edev") => {
            *response.status_mut() = StatusCode::CREATED;
            response
                .headers_mut()
                .insert(LOCATION, "/edev/4".parse().unwrap());
        }
        (&Method::GET, "/edev/3") => {
            *response.body_mut() = Body::from(ED_16_01_08);
        }
        (&Method::PUT, "/edev/3") => {
            *response.status_mut() = StatusCode::NO_CONTENT;
        }
        (&Method::DELETE, "/edev/3") => {
            *response.status_mut() = StatusCode::NO_CONTENT;
        }
        (&Method::GET, "/edev/4/fsal") => {
            *response.body_mut() = Body::from(FSAL_16_03_11);
        }
        (&Method::GET, "/edev/4") => {
            *response.body_mut() = Body::from(ED_16_03_06);
        }
        (&Method::GET, "/edev/5") => {
            *response.body_mut() = Body::from(ER_16_04_06);
        }
        (&Method::GET, "/edev/3/reg") => {
            *response.body_mut() = Body::from(REG_16_01_10);
        }
        (&Method::POST, "/rsp") => {
            *response.status_mut() = StatusCode::CREATED;
            // Location header is unset in examples, but is technically always required by spec?
            // Client will handle missing location header regardless.
        }
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    log::info!("Outgoing Response: {:?}", response);
    Ok(response)
}
