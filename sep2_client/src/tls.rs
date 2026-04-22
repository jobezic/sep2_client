//! TLS Configuration
//!
//! Provides an interface for parsing & verifying 2030.5 certificates, as per IEEE 2030.5 section 6.11
//!

use std::fs::File;
use std::future::Future;
use std::io::BufReader;
use std::net::IpAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Request};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
pub use rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
use rustls::{
    client::{ClientConfig, HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier, ServerName},
    version, Certificate, DigitallySignedStruct, Error as TlsError, PrivateKey, RootCertStore,
    SignatureScheme, SupportedCipherSuite,
};
use rustls_pemfile::Item;

#[cfg(feature = "pubsub")]
use rustls::server::{AllowAnyAuthenticatedClient, ServerConfig};
use x509_parser::{
    certificate::X509Certificate,
    extensions::GeneralName,
    prelude::ParsedExtension,
    time::ASN1Time,
};
use x509_verify::{
    der::asn1::ObjectIdentifier,
    spki::AlgorithmIdentifierRef,
    Message, Signature as X509Signature, VerifyInfo, VerifyingKey,
};

pub(crate) type HTTPSConnector = HttpsConnector<HttpConnector>;
pub(crate) type HTTPSClient = Client<HTTPSConnector, Body>;
pub(crate) type HTTPClient = Client<HttpConnector, Body>;
pub(crate) type TlsClientConfig = ClientConfig;

/// A trait for custom HTTP request handling, useful for mocking.
pub trait HttpRequester: Send + Sync {
    fn request(
        &self,
        req: Request<Body>,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<hyper::Response<Body>, hyper::Error>> + Send,
        >,
    >;
}

pub const DEFAULT_TLS_CLIENT_CIPHER_SUITE: SupportedCipherSuite =
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

const DEFAULT_TLS_CLIENT_CIPHER_SUITES: &[SupportedCipherSuite] = &[DEFAULT_TLS_CLIENT_CIPHER_SUITE];

#[derive(Clone)]
pub struct ClientTlsOptions {
    pub cipher_suite: SupportedCipherSuite,
    pub use_certificate_chain_file: bool,
}

impl Default for ClientTlsOptions {
    fn default() -> Self {
        Self {
            cipher_suite: DEFAULT_TLS_CLIENT_CIPHER_SUITE,
            use_certificate_chain_file: false,
        }
    }
}

#[derive(Clone)]
pub(crate) enum ClientInner {
    Https(HTTPSClient),
    Http(HTTPClient),
    Custom(Arc<dyn HttpRequester>),
}

impl ClientInner {
    pub(crate) fn request(
        &self,
        req: Request<Body>,
    ) -> Pin<Box<dyn Future<Output = std::result::Result<hyper::Response<Body>, hyper::Error>> + Send>>
    {
        match self {
            ClientInner::Https(c) => Box::pin(c.request(req)),
            ClientInner::Http(c) => Box::pin(c.request(req)),
            ClientInner::Custom(c) => c.request(req),
        }
    }
}

pub(crate) fn create_client_tls_cfg(
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
    rootca_path: impl AsRef<Path>,
) -> Result<TlsClientConfig> {
    create_client_tls_cfg_with_options(cert_path, pk_path, rootca_path, &ClientTlsOptions::default())
}

pub(crate) fn create_client_tls_cfg_with_options(
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
    rootca_path: impl AsRef<Path>,
    options: &ClientTlsOptions,
) -> Result<TlsClientConfig> {
    let rootca_path = rootca_path.as_ref();
    log::debug!("Resolving CipherSuite");
    let cipher_suites = std::slice::from_ref(&options.cipher_suite);
    log::debug!("Loading Certificate Authority File");
    let root_store = load_root_cert_store(rootca_path)?;
    let verifier = create_server_cert_verifier(rootca_path)?;
    log::debug!("Loading Certificate File");
    let cert_chain = if options.use_certificate_chain_file {
        load_certificates(cert_path)?
    } else {
        vec![read_certificate_der(cert_path)?]
    };
    log::debug!("Loading Private Key File");
    let private_key = load_private_key(pk_path)?;
    let mut config = ClientConfig::builder()
        .with_cipher_suites(cipher_suites)
        .with_kx_groups(&[&rustls::kx_group::SECP256R1])
        .with_protocol_versions(&[&version::TLS12])?
        .with_root_certificates(root_store)
        .with_client_auth_cert(cert_chain, private_key)?;
    config
        .dangerous()
        .set_certificate_verifier(verifier);
    Ok(config)
}

fn create_server_cert_verifier(rootca_path: &Path) -> Result<Arc<dyn ServerCertVerifier>> {
    Ok(Arc::new(PureRustServerCertVerifier::new(rootca_path)?))
}

pub(crate) fn create_client(
    tls_config: TlsClientConfig,
    tcp_keepalive: Option<Duration>,
) -> Client<HTTPSConnector, Body> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_keepalive(tcp_keepalive);
    let https = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_only()
        .enable_http1()
        .wrap_connector(http);
    Client::builder().build::<HTTPSConnector, hyper::Body>(https)
}

pub(crate) fn create_http_client(tcp_keepalive: Option<Duration>) -> Client<HttpConnector, Body> {
    let mut http = HttpConnector::new();
    http.enforce_http(false);
    http.set_keepalive(tcp_keepalive);
    Client::builder().build::<HttpConnector, hyper::Body>(http)
}

#[cfg(feature = "pubsub")]
pub(crate) type TlsServerConfig = Arc<ServerConfig>;

#[cfg(feature = "pubsub")]
pub(crate) fn create_server_tls_config(
    cert_path: impl AsRef<Path>,
    pk_path: impl AsRef<Path>,
    rootca_path: impl AsRef<Path>,
) -> Result<TlsServerConfig> {
    log::debug!("Resolving CipherSuite");
    let cipher_suites = DEFAULT_TLS_CLIENT_CIPHER_SUITES;
    log::debug!("Loading Certificate Authority File");
    let root_store = load_root_cert_store(rootca_path)?;
    let verifier = AllowAnyAuthenticatedClient::new(root_store);
    log::debug!("Loading Certificate File");
    let cert_chain = load_certificates(cert_path)?;
    log::debug!("Loading Private Key File");
    let private_key = load_private_key(pk_path)?;
    let config = ServerConfig::builder()
        .with_cipher_suites(cipher_suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&[&version::TLS12])?
        .with_client_cert_verifier(Arc::new(verifier))
        .with_single_cert(cert_chain, private_key)?;
    Ok(Arc::new(config))
}

fn load_root_cert_store(rootca_path: impl AsRef<Path>) -> Result<RootCertStore> {
    let path = rootca_path.as_ref();
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    if certs.is_empty() {
        bail!("No certificates found in {}", path.display());
    }

    let mut anchors = Vec::with_capacity(certs.len());

    for der in certs {
        let (_, cert) = x509_parser::parse_x509_certificate(&der)
            .map_err(|e| anyhow!("Invalid CA certificate in {}: {:?}", path.display(), e))?;

        let subject = der_sequence_contents(cert.subject().as_raw())?.to_vec();
        let spki = cert.public_key().raw.to_vec();
        let name_constraints = cert
            .extensions()
            .iter()
            .find_map(|ext| match ext.parsed_extension() {
                ParsedExtension::NameConstraints(_) => Some(ext.value.to_vec()),
                _ => None,
            });

        anchors.push(rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            subject,
            spki,
            name_constraints,
        ));
    }

    if anchors.is_empty() {
        bail!("Failed to parse any root certificates from {}", path.display());
    }

    let mut root_store = RootCertStore::empty();
    root_store.add_trust_anchors(anchors.into_iter());
    Ok(root_store)
}

struct PureRustServerCertVerifier {
    rootca_path: String,
    trust_anchors: Vec<Certificate>,
}

impl PureRustServerCertVerifier {
    fn new(rootca_path: impl AsRef<Path>) -> Result<Self> {
        let rootca_path = rootca_path.as_ref();
        let trust_anchors = load_certificates(rootca_path)?;
        Ok(Self {
            rootca_path: rootca_path.display().to_string(),
            trust_anchors,
        })
    }

    fn verify_certificate_chain(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        now: SystemTime,
    ) -> std::result::Result<(), TlsError> {
        let now = asn1_time_from_system(now)?;
        let end_entity = parse_x509_certificate(end_entity)?;
        let intermediates = parse_x509_certificates(intermediates)?;
        let trust_anchors = parse_x509_certificates(&self.trust_anchors)?;

        validate_certificate_time(&end_entity, now, "server certificate")?;
        validate_supported_critical_extensions(&end_entity, "server certificate")?;
        validate_end_entity_usages(&end_entity)?;
        validate_server_identity(&end_entity, server_name)?;
        verify_chain_to_trust_anchor(&end_entity, &intermediates, &trust_anchors, now, 0, &mut Vec::new())
            .map_err(|err| TlsError::General(format!(
                "server certificate verification failed against {}: {}",
                self.rootca_path,
                err,
            )))
    }
}

impl ServerCertVerifier for PureRustServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        self.verify_certificate_chain(end_entity, intermediates, server_name, now)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_handshake_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_handshake_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }

    fn request_scts(&self) -> bool {
        false
    }
}

fn verify_handshake_signature(
    message: &[u8],
    cert: &Certificate,
    dss: &DigitallySignedStruct,
    require_tls13_curve_match: bool,
) -> std::result::Result<HandshakeSignatureValid, TlsError> {
    let cert = parse_x509_certificate(cert)?;
    if require_tls13_curve_match {
        ensure_tls13_signature_curve(&cert, dss.scheme)?;
    }

    let key_info = x509_verify::spki::SubjectPublicKeyInfoRef::try_from(cert.public_key().raw)
        .map_err(|err| TlsError::General(format!("invalid certificate subject public key info: {err}")))?;
    let verifying_key = VerifyingKey::new(key_info)
        .map_err(|err| TlsError::General(format!("unsupported certificate public key for TLS signature verification: {err}")))?;
    let algorithm = tls_signature_algorithm_identifier(dss.scheme)?;
    let signature = X509Signature::from_ref(algorithm, dss.signature());
    let verify_info = VerifyInfo::new(Message::new(message), signature);

    verifying_key
        .verify(verify_info)
        .map_err(|err| TlsError::General(format!("invalid TLS handshake signature: {err}")))?;
    Ok(HandshakeSignatureValid::assertion())
}

fn tls_signature_algorithm_identifier(
    scheme: SignatureScheme,
) -> std::result::Result<AlgorithmIdentifierRef<'static>, TlsError> {
    let oid = match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2"),
        SignatureScheme::ECDSA_NISTP384_SHA384 => ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3"),
        SignatureScheme::RSA_PKCS1_SHA256 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11"),
        SignatureScheme::RSA_PKCS1_SHA384 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.12"),
        SignatureScheme::RSA_PKCS1_SHA512 => ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.13"),
        SignatureScheme::ED25519 => ObjectIdentifier::new_unwrap("1.3.101.112"),
        _ => {
            return Err(TlsError::General(format!(
                "unsupported TLS signature scheme {:?}",
                scheme,
            )))
        }
    };

    Ok(AlgorithmIdentifierRef {
        oid,
        parameters: None,
    })
}

fn ensure_tls13_signature_curve(
    cert: &X509Certificate<'_>,
    scheme: SignatureScheme,
) -> std::result::Result<(), TlsError> {
    let expected_curve = match scheme {
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some("1.2.840.10045.3.1.7"),
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some("1.3.132.0.34"),
        _ => None,
    };

    let Some(expected_curve) = expected_curve else {
        return Ok(());
    };

    let Some(parameters) = cert.public_key().algorithm.parameters.as_ref() else {
        return Err(TlsError::General(
            "ECDSA certificate is missing named-curve parameters".into(),
        ));
    };

    let actual_curve = ObjectIdentifier::from_bytes(parameters.data).map_err(|_| {
        TlsError::General("failed to parse ECDSA named-curve parameters".into())
    })?;

    if actual_curve == ObjectIdentifier::new_unwrap(expected_curve) {
        Ok(())
    } else {
        Err(TlsError::General(format!(
            "TLS 1.3 signature scheme {:?} is incompatible with certificate curve {}",
            scheme,
            actual_curve,
        )))
    }
}

fn parse_x509_certificate(cert: &Certificate) -> std::result::Result<X509Certificate<'_>, TlsError> {
    x509_parser::parse_x509_certificate(&cert.0)
        .map(|(_, cert)| cert)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))
}

fn parse_x509_certificates(certs: &[Certificate]) -> std::result::Result<Vec<X509Certificate<'_>>, TlsError> {
    certs.iter().map(parse_x509_certificate).collect()
}

fn asn1_time_from_system(time: SystemTime) -> std::result::Result<ASN1Time, TlsError> {
    let unix_time = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TlsError::General("system time predates UNIX_EPOCH".into()))?
        .as_secs();
    if unix_time > i64::MAX as u64 {
        return Err(TlsError::General(
            "system time exceeds supported certificate verification range".into(),
        ));
    }

    ASN1Time::from_timestamp(unix_time as i64)
        .map_err(|_| TlsError::General("failed to convert system time for certificate verification".into()))
}

fn validate_certificate_time(
    cert: &X509Certificate<'_>,
    now: ASN1Time,
    description: &str,
) -> std::result::Result<(), TlsError> {
    if cert.validity.is_valid_at(now) {
        Ok(())
    } else {
        Err(TlsError::General(format!("{description} is not valid at the current time")))
    }
}

fn validate_supported_critical_extensions(
    cert: &X509Certificate<'_>,
    description: &str,
) -> std::result::Result<(), TlsError> {
    for extension in cert.extensions() {
        if !extension.critical {
            continue;
        }

        let supported = matches!(
            extension.parsed_extension(),
            ParsedExtension::BasicConstraints(_)
                | ParsedExtension::CertificatePolicies(_)
                | ParsedExtension::ExtendedKeyUsage(_)
                | ParsedExtension::KeyUsage(_)
                | ParsedExtension::SubjectAlternativeName(_)
        );

        if !supported {
            return Err(TlsError::General(format!(
                "unsupported critical extension {} in {description}",
                extension.oid,
            )));
        }
    }

    Ok(())
}

fn validate_end_entity_usages(cert: &X509Certificate<'_>) -> std::result::Result<(), TlsError> {
    if let Some(key_usage) = cert
        .key_usage()
        .map_err(|err| TlsError::General(format!("invalid key usage extension: {err}")))?
    {
        if !key_usage.value.digital_signature() {
            return Err(TlsError::General(
                "server certificate key usage does not permit digital signatures".into(),
            ));
        }
    }

    if let Some(extended_key_usage) = cert
        .extended_key_usage()
        .map_err(|err| TlsError::General(format!("invalid extended key usage extension: {err}")))?
    {
        if !extended_key_usage.value.any && !extended_key_usage.value.server_auth {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::InvalidPurpose,
            ));
        }
    }

    Ok(())
}

fn validate_ca_certificate(
    cert: &X509Certificate<'_>,
    now: ASN1Time,
    subordinate_ca_count: usize,
) -> std::result::Result<(), TlsError> {
    validate_certificate_time(cert, now, "issuer certificate")?;
    validate_supported_critical_extensions(cert, "issuer certificate")?;

    let basic_constraints = cert
        .basic_constraints()
        .map_err(|err| TlsError::General(format!("invalid basic constraints extension: {err}")))?
        .ok_or_else(|| TlsError::General("issuer certificate is missing basic constraints".into()))?;
    if !basic_constraints.value.ca {
        return Err(TlsError::General(
            "issuer certificate is not marked as a CA certificate".into(),
        ));
    }
    if let Some(path_len_constraint) = basic_constraints.value.path_len_constraint {
        if subordinate_ca_count > path_len_constraint as usize {
            return Err(TlsError::General(format!(
                "issuer certificate path length constraint {} exceeded by {} subordinate CA certificates",
                path_len_constraint,
                subordinate_ca_count,
            )));
        }
    }

    if let Some(key_usage) = cert
        .key_usage()
        .map_err(|err| TlsError::General(format!("invalid issuer key usage extension: {err}")))?
    {
        if !key_usage.value.key_cert_sign() {
            return Err(TlsError::General(
                "issuer certificate key usage does not permit certificate signing".into(),
            ));
        }
    }

    if let Some(extended_key_usage) = cert
        .extended_key_usage()
        .map_err(|err| TlsError::General(format!("invalid issuer extended key usage extension: {err}")))?
    {
        if !extended_key_usage.value.any && !extended_key_usage.value.server_auth {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::InvalidPurpose,
            ));
        }
    }

    Ok(())
}

fn validate_server_identity(
    cert: &X509Certificate<'_>,
    server_name: &ServerName,
) -> std::result::Result<(), TlsError> {
    match server_name {
        ServerName::DnsName(name) => validate_dns_name(cert, name.as_ref()),
        ServerName::IpAddress(ip) => validate_ip_address(cert, *ip),
        _ => Err(TlsError::General(format!(
            "unsupported server name variant: {:?}",
            server_name,
        ))),
    }
}

fn validate_dns_name(cert: &X509Certificate<'_>, hostname: &str) -> std::result::Result<(), TlsError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|err| TlsError::General(format!("invalid subject alternative name extension: {err}")))?;

    if let Some(san) = san {
        if san
            .value
            .general_names
            .iter()
            .any(|name| matches!(name, GeneralName::DNSName(pattern) if dns_name_matches(pattern, hostname)))
        {
            return Ok(());
        }

        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ));
    }

    if cert
        .subject()
        .iter_common_name()
        .filter_map(|name| name.as_str().ok())
        .any(|pattern| dns_name_matches(pattern, hostname))
    {
        return Ok(());
    }

    Err(TlsError::InvalidCertificate(
        rustls::CertificateError::NotValidForName,
    ))
}

fn validate_ip_address(cert: &X509Certificate<'_>, ip: IpAddr) -> std::result::Result<(), TlsError> {
    let san = cert
        .subject_alternative_name()
        .map_err(|err| TlsError::General(format!("invalid subject alternative name extension: {err}")))?
        .ok_or(TlsError::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ))?;

    if san
        .value
        .general_names
        .iter()
        .any(|name| matches!(name, GeneralName::IPAddress(bytes) if ip_address_matches(bytes, ip)))
    {
        Ok(())
    } else {
        Err(TlsError::InvalidCertificate(
            rustls::CertificateError::NotValidForName,
        ))
    }
}

fn dns_name_matches(pattern: &str, hostname: &str) -> bool {
    let pattern = pattern.trim_end_matches('.');
    let hostname = hostname.trim_end_matches('.');
    if pattern.eq_ignore_ascii_case(hostname) {
        return true;
    }

    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    if suffix.contains('*') {
        return false;
    }

    let hostname_labels: Vec<&str> = hostname.split('.').collect();
    let suffix_labels: Vec<&str> = suffix.split('.').collect();
    hostname_labels.len() == suffix_labels.len() + 1
        && hostname_labels[1..]
            .iter()
            .zip(suffix_labels.iter())
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn ip_address_matches(bytes: &[u8], ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => bytes == ip.octets().as_slice(),
        IpAddr::V6(ip) => bytes == ip.octets().as_slice(),
    }
}

fn verify_chain_to_trust_anchor(
    current: &X509Certificate<'_>,
    intermediates: &[X509Certificate<'_>],
    trust_anchors: &[X509Certificate<'_>],
    now: ASN1Time,
    subordinate_ca_count: usize,
    used_intermediates: &mut Vec<usize>,
) -> std::result::Result<(), TlsError> {
    for anchor in trust_anchors {
        if !certificate_is_issued_by(current, anchor) {
            continue;
        }

        validate_ca_certificate(anchor, now, subordinate_ca_count)?;
        return Ok(());
    }

    let mut last_error = None;

    for (index, issuer) in intermediates.iter().enumerate() {
        if used_intermediates.contains(&index) || !certificate_is_issued_by(current, issuer) {
            continue;
        }

        match validate_ca_certificate(issuer, now, subordinate_ca_count).and_then(|_| {
            used_intermediates.push(index);
            let result = verify_chain_to_trust_anchor(
                issuer,
                intermediates,
                trust_anchors,
                now,
                subordinate_ca_count + 1,
                used_intermediates,
            );
            used_intermediates.pop();
            result
        }) {
            Ok(()) => return Ok(()),
            Err(err) => last_error = Some(err),
        }
    }

    Err(last_error.unwrap_or(TlsError::InvalidCertificate(
        rustls::CertificateError::UnknownIssuer,
    )))
}

fn certificate_is_issued_by(
    certificate: &X509Certificate<'_>,
    issuer: &X509Certificate<'_>,
) -> bool {
    certificate.issuer() == issuer.subject()
        && certificate.verify_signature(Some(issuer.public_key())).is_ok()
}

fn der_sequence_contents(input: &[u8]) -> Result<&[u8]> {
    if input.len() < 2 || input[0] != 0x30 {
        bail!("subject name is not a DER SEQUENCE");
    }

    let (len_len, content_len) = if input[1] & 0x80 == 0 {
        (1usize, input[1] as usize)
    } else {
        let bytes = (input[1] & 0x7f) as usize;
        if bytes == 0 || input.len() < 2 + bytes {
            bail!("invalid DER length in subject name");
        }
        let mut len = 0usize;
        for &byte in &input[2..2 + bytes] {
            len = (len << 8) | byte as usize;
        }
        (1 + bytes, len)
    };

    let start = 1 + len_len;
    let end = start
        .checked_add(content_len)
        .ok_or_else(|| anyhow!("subject name length overflow"))?;
    if end != input.len() {
        bail!("unexpected trailing bytes in subject name");
    }

    Ok(&input[start..end])
}

fn load_certificates(cert_path: impl AsRef<Path>) -> Result<Vec<Certificate>> {
    let path = cert_path.as_ref();
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)?;
    if certs.is_empty() {
        bail!("No certificates found in {}", path.display());
    }
    Ok(certs.into_iter().map(Certificate).collect())
}

fn read_certificate_der(cert_path: impl AsRef<Path>) -> Result<Certificate> {
    let path = cert_path.as_ref();
    let certs = load_certificates(path)?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("No certificate found in {}", path.display()))
}

fn load_private_key(pk_path: impl AsRef<Path>) -> Result<PrivateKey> {
    let path = pk_path.as_ref();
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);

    for item in rustls_pemfile::read_all(&mut reader)? {
        match item {
            Item::PKCS8Key(key) | Item::RSAKey(key) | Item::ECKey(key) => {
                return Ok(PrivateKey(key));
            }
            _ => continue,
        }
    }

    bail!("No private key found in {}", path.display())
}

// We use `x509_parser` to parse and verify that the required extensions are present,
// for both self-signed Client Certificates and device certificates, as per the specification.

/// Verify that the PEM encoded certificate at the given path meets IEEE 2030.5 "Device Certificate" requirements.
///
/// Newly purchased or acquired certificates in an IEEE 2030.5 certificate chain will satisfy these requirements.
///
/// Currently this function isn't called when instantiating a [`Client`]` nor a [`ClientNotifServer`], but that may change in the future.
///
///
/// A valid 'device certificate' *must* be used by a [`ClientNotifServer`], i.e. NOT a self signed certificate
/// "The use of TLS (IETF RFC 5246) requires that all hosts implementing server functionality SHALL use a
/// device certificate whereby the server presents its device certificate as part of the TLS handshake"
///
/// See section 6.11.8.3.3 for more.
///
/// [`Client`]: crate::client::Client
/// [`ClientNotifServer`]: crate::pubsub::ClientNotifServer
pub fn check_device_cert(cert_path: impl AsRef<Path>) -> Result<()> {
    let contents = std::fs::read(cert_path)?;
    let (_rem, cert) = x509_parser::pem::parse_x509_pem(&contents)?;
    let cert = cert.parse_x509()?;
    // TODO: Check Issued by & Subject name
    let exts = cert.extensions();
    let mut key_usage = false;
    let mut certificate_policies = false;
    let mut san = false;
    let mut aki = false;
    for ext in exts {
        let critical = ext.critical;
        match ext.parsed_extension() {
            // "certificates containing policy mappings MUST be rejected"
            ParsedExtension::PolicyMappings(_) => {
                bail!("Device Certificates cannot contain policy mappings.")
            }
            // "Name-constraints are not supported and certificates containing name-constraints MUST be rejected."
            ParsedExtension::NameConstraints(_) => {
                bail!("Device Certificates cannot contain name constraints.")
            }
            // TODO: What do we need to examine inside the rest of these extensions? What can we reasonably check?
            ParsedExtension::CertificatePolicies(_) => {
                if critical {
                    certificate_policies = true;
                } else {
                    bail!("CertificatePolicies extension must be critical.")
                }
            }
            ParsedExtension::SubjectAlternativeName(_) => {
                if critical {
                    san = true;
                } else {
                    bail!("SubjectAlternativeName extension must be critical")
                }
            }
            ParsedExtension::KeyUsage(_) => {
                if critical {
                    key_usage = true;
                } else {
                    bail!("KeyUsage extension must be critical.")
                }
            }
            ParsedExtension::AuthorityKeyIdentifier(_) => {
                if critical {
                    bail!("AuthorityKeyIdentifier extension cannot be critical.")
                } else {
                    aki = true;
                }
            }
            ParsedExtension::SubjectKeyIdentifier(_) => {
                if critical {
                    bail!("SubjectKeyIdentifier cannot be critical")
                }
            }
            // All other extensions constitute an invalid certificate
            // TODO: This might need to be relaxed to allow for modifications
            _ => bail!("Unexpected extension or unparsed extension encountered."),
        }
    }
    if !key_usage {
        bail!("KeyUsage extension not present")
    }
    if !certificate_policies {
        bail!("CertificatePolicies extension not present")
    }
    if !san {
        bail!("SubjectAlternativeName extension not present")
    }
    if !aki {
        bail!("AuthorityKeyIdentifier extension not present")
    }
    Ok(())
}

/// Verify that the PEM encoded certificate at the given path meets IEEE 2030.5 "Self Signed Client Certificate" requirements.
///
/// See Section 6.11.8.4.3 for more
pub fn check_self_signed_client_cert(cert_path: impl AsRef<Path>) -> Result<()> {
    let contents = std::fs::read(cert_path)?;
    let (_rem, cert) = x509_parser::pem::parse_x509_pem(&contents)?;
    let cert = cert.parse_x509()?;
    let exts = cert.extensions();
    let mut key_usage = false;
    let mut certificate_policies = false;
    // TODO: Check Issued by, Subject Name, Issuer Name, Validity, and Subject Public Key and Signature
    for ext in exts {
        let critical = ext.critical;
        match ext.parsed_extension() {
            // "certificates containing policy mappings MUST be rejected"
            ParsedExtension::PolicyMappings(_) => {
                bail!("Device Certificates cannot contain policy mappings.")
            }
            // "Name-constraints are not supported and certificates containing name-constraints MUST be rejected."
            ParsedExtension::NameConstraints(_) => {
                bail!("Device Certificates cannot contain name constraints.")
            }
            ParsedExtension::CertificatePolicies(_) => {
                if critical {
                    certificate_policies = true;
                } else {
                    bail!("CertificatePolicies extension must be critical.")
                }
            }
            ParsedExtension::KeyUsage(_) => {
                if critical {
                    key_usage = true;
                } else {
                    bail!("KeyUsage extension must be critical.")
                }
            }
            ParsedExtension::SubjectKeyIdentifier(_) => {
                if critical {
                    bail!("SubjectKeyIdentifier cannot be critical")
                }
            }
            // All other extensions constitute an invalid certificate
            // TODO: This might need to be relaxed to allow for modifications
            _ => bail!("Unexpected extension or unparsed extension encountered."),
        }
    }
    if !key_usage {
        bail!("KeyUsage extension not present.")
    }
    if !certificate_policies {
        bail!("CertificatePolicies extension not present.")
    }
    Ok(())
}

pub fn check_ca(cert_path: impl AsRef<Path>) -> Result<()> {
    let contents = std::fs::read(cert_path)?;
    let (_rem, cert) = x509_parser::pem::parse_x509_pem(&contents)?;
    let cert = cert.parse_x509()?;
    let exts = cert.extensions();
    let mut key_usage = false;
    let mut certificate_policies = false;
    let mut basic_constraints = false;
    let mut ski = false;
    for ext in exts {
        let critical = ext.critical;
        match ext.parsed_extension() {
            ParsedExtension::CertificatePolicies(_) => {
                if critical {
                    certificate_policies = true;
                } else {
                    bail!("CertificatePolicies extension must be critical.")
                }
            }
            ParsedExtension::KeyUsage(ku) => {
                if critical && ku.crl_sign() && ku.key_cert_sign() {
                    key_usage = true;
                } else {
                    bail!("KeyUsage extension must be critical and keyCertSign and crlSign must be true.")
                }
            }
            ParsedExtension::BasicConstraints(bc) => {
                if critical && bc.path_len_constraint.is_none() && bc.ca {
                    basic_constraints = true;
                } else {
                    bail!("BasicConstraints must be critical, cA must be true, and pathLen must be absent.")
                }
            }
            ParsedExtension::SubjectKeyIdentifier(_) => {
                if critical {
                    bail!("SubjectKeyIdentifier cannot be critical")
                } else {
                    ski = true;
                }
            }
            _ => bail!("Unexpected extension or unparsed extension encountered."),
        }
    }
    if !key_usage {
        bail!("KeyUsage extension not present.")
    }
    if !certificate_policies {
        bail!("CertificatePolicies extension not present.")
    }
    if !basic_constraints {
        bail!("BasicConstraints extension not present.")
    }
    if !ski {
        bail!("SubjectKeyIdentifier extension not present.")
    }
    Ok(())
}

// TODO: Should we do checks on the supplied root ca?
