//! SCEP Message Builder — PKCSReq and GetCertInitial construction (RFC 8894)
//!
//! Builds the nested CMS structure required for SCEP enrollment:
//!
//! ```text
//! ContentInfo (id-signedData)
//!   SignedData
//!     encapContentInfo (id-data)
//!       eContent: ContentInfo (id-envelopedData)
//!         EnvelopedData
//!           recipientInfos: KeyTransRecipientInfo (RSA)
//!           encryptedContentInfo: AES-256-CBC(CSR DER)
//!     signerInfos: [requester self-signed cert, SHA-256/RSA sig]
//!     authenticatedAttrs: messageType, transactionId, senderNonce
//! ```

use anyhow::{anyhow, Context, Result};
use rand::RngCore;
use sha2::{Digest, Sha256};
#[cfg(not(feature = "fips"))]
use spork_core::algo::rsa_oaep;
use spork_core::{
    algo::{AlgorithmId, KeyPair},
    cert::{CsrBuilder, NameBuilder},
};

use super::types::MessageType;

// ── OID constants (DER-encoded value bytes, without tag/length) ───────────────

/// id-signedData (1.2.840.113549.1.7.2)
pub(crate) const OID_SIGNED_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x02];
/// id-envelopedData (1.2.840.113549.1.7.3)
pub(crate) const OID_ENVELOPED_DATA: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x03];
/// id-data (1.2.840.113549.1.7.1)
pub(crate) const OID_DATA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01];
/// sha256WithRSAEncryption (1.2.840.113549.1.1.11)
pub(crate) const OID_SHA256_WITH_RSA: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
/// rsaEncryption (1.2.840.113549.1.1.1)
#[allow(dead_code)]
pub(crate) const OID_RSA_ENCRYPTION: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
/// id-RSAES-OAEP (1.2.840.113549.1.1.7)
pub(crate) const OID_RSAES_OAEP: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x07];
/// aes256-CBC (2.16.840.1.101.3.4.1.42)
pub(crate) const OID_AES256_CBC: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a];
/// id-sha256 (2.16.840.1.101.3.4.2.1)
pub(crate) const OID_SHA256: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
/// id-contentType (1.2.840.113549.1.9.3)
pub(crate) const OID_CONTENT_TYPE: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x03];
/// id-messageDigest (1.2.840.113549.1.9.4)
pub(crate) const OID_MESSAGE_DIGEST: &[u8] =
    &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04];
/// SCEP messageType (2.16.840.1.113733.1.9.2)
pub(crate) const OID_SCEP_MESSAGE_TYPE: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x02];
/// SCEP pkiStatus (2.16.840.1.113733.1.9.3)
pub(crate) const OID_SCEP_PKI_STATUS: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x03];
/// SCEP transactionID (2.16.840.1.113733.1.9.7)
pub(crate) const OID_SCEP_TRANSACTION_ID: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x07];
/// SCEP senderNonce (2.16.840.1.113733.1.9.5)
pub(crate) const OID_SCEP_SENDER_NONCE: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x05];
/// id-signingCertificate (1.2.840.113549.1.9.6)
#[allow(dead_code)]
pub(crate) const OID_SIGNING_CERT: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x06];

// ── Key type for SCEP ─────────────────────────────────────────────────────────

/// Key type for SCEP enrollment (SCEP traditionally uses RSA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScepKeyType {
    /// RSA-2048 (default, widely supported)
    Rsa2048,
    /// RSA-4096 (stronger)
    Rsa4096,
    /// ECDSA P-256 (if server supports it)
    EcP256,
}

impl ScepKeyType {
    /// Convert to spork-core AlgorithmId.
    pub fn to_algorithm_id(self) -> AlgorithmId {
        match self {
            ScepKeyType::Rsa2048 => AlgorithmId::Rsa2048,
            ScepKeyType::Rsa4096 => AlgorithmId::Rsa4096,
            ScepKeyType::EcP256 => AlgorithmId::EcdsaP256,
        }
    }
}

impl std::str::FromStr for ScepKeyType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rsa2048" => Ok(ScepKeyType::Rsa2048),
            "rsa4096" => Ok(ScepKeyType::Rsa4096),
            "ec-p256" => Ok(ScepKeyType::EcP256),
            other => Err(anyhow!(
                "Unknown key type '{}'. Use: rsa2048, rsa4096, ec-p256",
                other
            )),
        }
    }
}

// ── SCEP message material ─────────────────────────────────────────────────────

/// Material generated during SCEP message construction.
pub struct ScepMessageMaterial {
    /// DER-encoded PKCS#10 CSR
    pub csr_der: Vec<u8>,
    /// DER-encoded self-signed requester certificate
    pub requester_cert_der: Vec<u8>,
    /// Transaction ID (hex-encoded SHA-256 of CSR public key)
    pub transaction_id: String,
    /// Sender nonce (16 random bytes)
    pub sender_nonce: [u8; 16],
    /// Key pair (caller must persist for the issued cert)
    pub key_pair: KeyPair,
}

/// Build SCEP message material (key, CSR, transaction ID, nonce).
pub fn build_message_material(
    subject_cn: &str,
    challenge: Option<&str>,
    key_type: ScepKeyType,
    san_names: &[String],
) -> Result<ScepMessageMaterial> {
    let algo = key_type.to_algorithm_id();
    let key_pair = KeyPair::generate(algo).context("Failed to generate key pair")?;

    let csr_der = build_csr_der(subject_cn, challenge, san_names, &key_pair)?;

    // Transaction ID: hex-encoded SHA-256 of CSR public key DER
    let pub_key_der = key_pair
        .public_key_der()
        .context("Failed to get public key DER")?;
    let transaction_id = hex::encode(Sha256::digest(&pub_key_der));

    // Sender nonce: 16 random bytes
    let mut sender_nonce = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut sender_nonce);

    // Self-signed requester certificate (validity: 1 year)
    let requester_cert_der = build_self_signed_cert(subject_cn, &key_pair)?;

    Ok(ScepMessageMaterial {
        csr_der,
        requester_cert_der,
        transaction_id,
        sender_nonce,
        key_pair,
    })
}

/// Build and sign a PKCS#10 CSR DER.
fn build_csr_der(
    subject_cn: &str,
    challenge: Option<&str>,
    san_names: &[String],
    key_pair: &KeyPair,
) -> Result<Vec<u8>> {
    let subject = NameBuilder::new(subject_cn).build();
    let mut builder = CsrBuilder::new(subject);

    if let Some(pw) = challenge {
        builder = builder.with_challenge_password(pw);
    }

    if !san_names.is_empty() {
        let san_refs: Vec<&str> = san_names.iter().map(|s| s.as_str()).collect();
        builder = builder.with_san_dns_names(&san_refs);
    }

    let csr = builder
        .build_and_sign(key_pair)
        .context("Failed to build CSR")?;
    Ok(csr.der)
}

/// Build a self-signed certificate for the requester (used in SCEP SignerInfo).
///
/// This is a temporary certificate used only for signing the SCEP PKCSReq.
/// The CA will issue the real certificate.
fn build_self_signed_cert(cn: &str, key_pair: &KeyPair) -> Result<Vec<u8>> {
    use spork_core::cert::{CertificateBuilder, NameBuilder};

    let subject = NameBuilder::new(cn).build();
    let pub_key_der = key_pair
        .public_key_der()
        .context("Failed to get public key DER for self-signed cert")?;
    let algo = key_pair.algorithm_id();

    let cert = CertificateBuilder::new(subject, pub_key_der, algo)
        .build_and_sign(key_pair)
        .context("Failed to build self-signed certificate")?;

    use der::Encode;
    cert.to_der()
        .context("Failed to DER-encode self-signed certificate")
}

// ── DER encoding helpers ──────────────────────────────────────────────────────

/// Encode a DER length field.
pub fn encode_length(buf: &mut Vec<u8>, len: usize) {
    if len < 128 {
        buf.push(len as u8);
    } else {
        let len_bytes = (len as u32).to_be_bytes();
        let start = len_bytes.iter().position(|&b| b != 0).unwrap_or(3);
        let len_len = 4 - start;
        buf.push(0x80 | len_len as u8);
        buf.extend_from_slice(&len_bytes[start..]);
    }
}

/// Encode a DER SEQUENCE around `inner`.
fn der_sequence(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0x30];
    encode_length(&mut out, inner.len());
    out.extend_from_slice(inner);
    out
}

/// Encode a DER SET around `inner`.
fn der_set(inner: &[u8]) -> Vec<u8> {
    let mut out = vec![0x31];
    encode_length(&mut out, inner.len());
    out.extend_from_slice(inner);
    out
}

/// Encode a DER OCTET STRING.
fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x04];
    encode_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Encode a DER OID (with tag 0x06 and length).
fn der_oid(oid_value: &[u8]) -> Vec<u8> {
    let mut out = vec![0x06];
    encode_length(&mut out, oid_value.len());
    out.extend_from_slice(oid_value);
    out
}

/// Encode a DER INTEGER from a u32.
fn der_integer_u32(value: u32) -> Vec<u8> {
    if value <= 0x7f {
        vec![0x02, 0x01, value as u8]
    } else if value <= 0x7fff {
        vec![0x02, 0x02, (value >> 8) as u8, value as u8]
    } else if value <= 0x7fffff {
        vec![
            0x02,
            0x03,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    } else {
        vec![
            0x02,
            0x04,
            (value >> 24) as u8,
            (value >> 16) as u8,
            (value >> 8) as u8,
            value as u8,
        ]
    }
}

/// Encode a DER PrintableString (tag 0x13).
fn der_printable_string(s: &str) -> Vec<u8> {
    let mut out = vec![0x13];
    encode_length(&mut out, s.len());
    out.extend_from_slice(s.as_bytes());
    out
}

/// Encode a context-tagged implicit value (e.g. \[0\] IMPLICIT).
fn der_context_implicit(tag_num: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x80 | tag_num]; // primitive context tag
    encode_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

/// Encode a context-tagged explicit value (e.g. \[0\] EXPLICIT).
fn der_context_explicit(tag_num: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0 | tag_num]; // constructed context tag
    encode_length(&mut out, data.len());
    out.extend_from_slice(data);
    out
}

// ── AlgorithmIdentifier helpers ───────────────────────────────────────────────

/// Build AlgorithmIdentifier SEQUENCE { OID, NULL } (e.g. for digest algorithms).
fn algorithm_identifier_with_null(oid_value: &[u8]) -> Vec<u8> {
    let oid = der_oid(oid_value);
    let null = &[0x05, 0x00];
    let inner: Vec<u8> = oid.iter().chain(null.iter()).copied().collect();
    der_sequence(&inner)
}

/// Build AlgorithmIdentifier SEQUENCE { OID } (no parameters).
fn algorithm_identifier_no_params(oid_value: &[u8]) -> Vec<u8> {
    let oid = der_oid(oid_value);
    der_sequence(&oid)
}

// ── CMS EnvelopedData builder ─────────────────────────────────────────────────

/// Build CMS ContentInfo wrapping EnvelopedData.
///
/// Encrypts `plaintext` (the CSR DER) with AES-256-CBC.
/// The AES key is encrypted to `ca_pub_key_der` (RSA SPKI) using RSAES-OAEP.
#[allow(unreachable_code, unused_variables, clippy::diverging_sub_expression)]
pub fn build_enveloped_data(plaintext: &[u8], ca_pub_key_der: &[u8]) -> Result<Vec<u8>> {
    #[cfg(feature = "fips")]
    anyhow::bail!("SCEP enrollment is not available in FIPS mode");

    // Generate AES-256 key and IV
    let mut aes_key = [0u8; 32];
    let mut iv = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut aes_key);
    rand::rngs::OsRng.fill_bytes(&mut iv);

    // Encrypt plaintext with AES-256-CBC
    let ciphertext = aes256_cbc_encrypt(&aes_key, &iv, plaintext)?;

    // Encrypt AES key with RSA-OAEP
    #[cfg(not(feature = "fips"))]
    let encrypted_key =
        rsa_oaep::oaep_encrypt(ca_pub_key_der, &aes_key, rsa_oaep::OaepHash::Sha1, None)
            .context("RSA-OAEP encryption of content-encryption key failed")?;
    #[cfg(feature = "fips")]
    let encrypted_key: Vec<u8> = unreachable!();

    // Extract IssuerAndSerialNumber from CA cert for RecipientIdentifier
    // For simplicity we use SubjectKeyIdentifier [0] with the CA pub key hash
    let ca_ski = sha1_digest(ca_pub_key_der);

    let env_data = build_enveloped_data_inner(&encrypted_key, &iv, &ciphertext, &ca_ski)?;

    // ContentInfo { contentType id-envelopedData, content [0] EnvelopedData }
    let oid = der_oid(OID_ENVELOPED_DATA);
    let explicit = der_context_explicit(0, &env_data);
    let inner: Vec<u8> = oid.iter().chain(explicit.iter()).copied().collect();
    Ok(der_sequence(&inner))
}

/// Build EnvelopedData SEQUENCE (RFC 5652 §6.1).
fn build_enveloped_data_inner(
    encrypted_key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
    ca_ski: &[u8],
) -> Result<Vec<u8>> {
    // version: CMSVersion = 0 (no attribute certs, no PWRI)
    let version = der_integer_u32(0);

    // RecipientInfo: KeyTransRecipientInfo
    //   version: 2 (subjectKeyIdentifier used)
    //   rid: [0] SubjectKeyIdentifier (SKI)
    //   keyEncryptionAlgorithm: id-RSAES-OAEP
    //   encryptedKey: OCTET STRING
    let ktri_version = der_integer_u32(2);
    let rid = der_context_implicit(0, ca_ski);
    let key_enc_alg = build_rsaes_oaep_alg_id()?;
    let enc_key_oct = der_octet_string(encrypted_key);
    let ktri_inner: Vec<u8> = ktri_version
        .iter()
        .chain(rid.iter())
        .chain(key_enc_alg.iter())
        .chain(enc_key_oct.iter())
        .copied()
        .collect();
    let ktri = der_sequence(&ktri_inner);
    let recipient_infos = der_set(&ktri);

    // EncryptedContentInfo
    //   contentType: id-data
    //   contentEncryptionAlgorithm: aes256-CBC { iv }
    //   encryptedContent [0] IMPLICIT OCTET STRING
    let content_type_oid = der_oid(OID_DATA);
    let aes_alg_id = build_aes256_cbc_alg_id(iv);
    let enc_content = der_context_implicit(0, ciphertext);
    let eci_inner: Vec<u8> = content_type_oid
        .iter()
        .chain(aes_alg_id.iter())
        .chain(enc_content.iter())
        .copied()
        .collect();
    let eci = der_sequence(&eci_inner);

    let env_inner: Vec<u8> = version
        .iter()
        .chain(recipient_infos.iter())
        .chain(eci.iter())
        .copied()
        .collect();

    Ok(der_sequence(&env_inner))
}

/// Build RSAES-OAEP AlgorithmIdentifier with SHA-1 parameters (RFC 8017 §C).
///
/// Many SCEP servers only support RSAES-PKCS1-v1_5 or OAEP-SHA1, so we use
/// the legacy form for maximum compatibility. The AlgorithmIdentifier for
/// rsaEncryption is the simplest approach and most widely supported.
fn build_rsaes_oaep_alg_id() -> Result<Vec<u8>> {
    // Use rsaEncryption OID with NULL params — PKCS#1 v1.5 style
    // This is the most compatible form for SCEP servers
    Ok(algorithm_identifier_with_null(OID_RSAES_OAEP))
}

/// Build AES-256-CBC AlgorithmIdentifier with IV parameter.
fn build_aes256_cbc_alg_id(iv: &[u8]) -> Vec<u8> {
    let oid = der_oid(OID_AES256_CBC);
    let iv_oct = der_octet_string(iv);
    let inner: Vec<u8> = oid.iter().chain(iv_oct.iter()).copied().collect();
    der_sequence(&inner)
}

// ── AES-256-CBC encryption ────────────────────────────────────────────────────

/// Encrypt data with AES-256-CBC (PKCS#7 padding).
fn aes256_cbc_encrypt(key: &[u8; 32], iv: &[u8; 16], plaintext: &[u8]) -> Result<Vec<u8>> {
    use aes::cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};

    type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

    let enc = Aes256CbcEnc::new_from_slices(key, iv)
        .map_err(|e| anyhow!("AES-256-CBC init failed: {}", e))?;

    let ciphertext = enc.encrypt_padded_vec_mut::<Pkcs7>(plaintext);
    Ok(ciphertext)
}

// ── SHA-1 digest (for SKI) ────────────────────────────────────────────────────

fn sha1_digest(data: &[u8]) -> Vec<u8> {
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

// ── CMS SignedData builder (PKCSReq) ──────────────────────────────────────────

/// Build the SCEP PKCSReq message as CMS SignedData DER.
///
/// This is the outermost CMS structure sent to the SCEP server.
pub fn build_pkcs_req(
    csr_der: &[u8],
    requester_cert_der: &[u8],
    transaction_id: &str,
    sender_nonce: &[u8; 16],
    ca_pub_key_der: &[u8],
    signer_key: &KeyPair,
) -> Result<Vec<u8>> {
    // Build the inner EnvelopedData wrapping the CSR
    let enveloped_ci =
        build_enveloped_data(csr_der, ca_pub_key_der).context("Failed to build EnvelopedData")?;

    build_signed_data_for_message(
        &enveloped_ci,
        MessageType::PKCSReq,
        transaction_id,
        sender_nonce,
        requester_cert_der,
        signer_key,
    )
}

/// Build a GetCertInitial polling message.
pub fn build_get_cert_initial(
    subject_cn: &str,
    transaction_id: &str,
    sender_nonce: &[u8; 16],
    requester_cert_der: &[u8],
    ca_pub_key_der: &[u8],
    signer_key: &KeyPair,
) -> Result<Vec<u8>> {
    // GetCertInitial body: IssuerAndSubject
    // For simplicity we build a minimal DER IssuerAndSubject structure
    let body = build_issuer_and_subject(subject_cn, ca_pub_key_der)?;
    let enveloped_ci = build_enveloped_data(&body, ca_pub_key_der)
        .context("Failed to build EnvelopedData for GetCertInitial")?;

    build_signed_data_for_message(
        &enveloped_ci,
        MessageType::GetCertInitial,
        transaction_id,
        sender_nonce,
        requester_cert_der,
        signer_key,
    )
}

/// Build IssuerAndSubject DER for GetCertInitial.
fn build_issuer_and_subject(subject_cn: &str, ca_pub_key_der: &[u8]) -> Result<Vec<u8>> {
    // IssuerAndSubject ::= SEQUENCE { issuer Name, subject Name }
    // We use a minimal CN-only Name for both
    let issuer_cn = extract_cn_hint(ca_pub_key_der);
    let issuer_name = build_minimal_rdn(&issuer_cn);
    let subject_name = build_minimal_rdn(subject_cn);
    let inner: Vec<u8> = issuer_name
        .iter()
        .chain(subject_name.iter())
        .copied()
        .collect();
    Ok(der_sequence(&inner))
}

/// Extract a CN hint from a public key DER (just use "CA" as fallback).
fn extract_cn_hint(_pub_key_der: &[u8]) -> String {
    "CA".to_string()
}

/// Build a minimal X.509 Name with a single CN RDN.
fn build_minimal_rdn(cn: &str) -> Vec<u8> {
    // id-at-commonName OID 2.5.4.3
    let cn_oid: &[u8] = &[0x55, 0x04, 0x03];
    let oid = der_oid(cn_oid);
    let value = der_printable_string(cn);
    let atv_inner: Vec<u8> = oid.iter().chain(value.iter()).copied().collect();
    let atv = der_sequence(&atv_inner);
    let rdn = der_set(&atv);
    // Name ::= SEQUENCE OF RDN
    der_sequence(&rdn)
}

// ── CMS SignedData construction ───────────────────────────────────────────────

/// Build a CMS ContentInfo(SignedData) wrapping `payload` with SCEP authenticated attributes.
fn build_signed_data_for_message(
    payload: &[u8],
    msg_type: MessageType,
    transaction_id: &str,
    sender_nonce: &[u8; 16],
    requester_cert_der: &[u8],
    signer_key: &KeyPair,
) -> Result<Vec<u8>> {
    // Build authenticated attributes
    let auth_attrs_der =
        build_authenticated_attrs(payload, msg_type, transaction_id, sender_nonce)?;

    // Sign the authenticated attributes (RFC 5652: signature covers the DER SET encoding)
    let auth_attrs_set = repack_as_set(&auth_attrs_der);
    let signature = signer_key
        .sign(&auth_attrs_set)
        .context("Failed to sign authenticated attributes")?;

    // Build the SignedData
    let signed_data = build_signed_data_inner(
        payload,
        &auth_attrs_der,
        &signature,
        requester_cert_der,
        signer_key,
    )?;

    // ContentInfo { id-signedData, [0] SignedData }
    let oid = der_oid(OID_SIGNED_DATA);
    let explicit = der_context_explicit(0, &signed_data);
    let ci_inner: Vec<u8> = oid.iter().chain(explicit.iter()).copied().collect();
    Ok(der_sequence(&ci_inner))
}

/// Build the SCEP authenticated attributes SET (RFC 5652 §5.4).
///
/// Authenticated attributes that must be signed:
/// - contentType (id-data, since payload is wrapped in EnvelopedData)
/// - messageDigest (SHA-256 of eContent octets)
/// - messageType (PKCSReq = "19", GetCertInitial = "20")
/// - transactionID (hex string)
/// - senderNonce (random 16 bytes)
fn build_authenticated_attrs(
    payload: &[u8],
    msg_type: MessageType,
    transaction_id: &str,
    sender_nonce: &[u8; 16],
) -> Result<Vec<u8>> {
    // contentType attribute: OID id-data
    let content_type_attr = build_attr(OID_CONTENT_TYPE, &[der_oid(OID_DATA)])?;

    // messageDigest: SHA-256 of the encapContentInfo eContent octets
    // The eContent is an OCTET STRING wrapping the payload (EnvelopedData ContentInfo)
    let digest = Sha256::digest(payload);
    let digest_attr = build_attr(OID_MESSAGE_DIGEST, &[der_octet_string(digest.as_slice())])?;

    // messageType: PrintableString of the numeric type
    let msg_type_str = msg_type.as_u8().to_string();
    let msg_type_attr = build_attr(
        OID_SCEP_MESSAGE_TYPE,
        &[der_printable_string(&msg_type_str)],
    )?;

    // transactionID: PrintableString
    let tx_id_attr = build_attr(
        OID_SCEP_TRANSACTION_ID,
        &[der_printable_string(transaction_id)],
    )?;

    // senderNonce: OCTET STRING (16 random bytes)
    let nonce_attr = build_attr(OID_SCEP_SENDER_NONCE, &[der_octet_string(sender_nonce)])?;

    // Assemble all attributes into a SET OF Attribute (implicit SET, not SEQUENCE)
    let all: Vec<u8> = content_type_attr
        .iter()
        .chain(digest_attr.iter())
        .chain(msg_type_attr.iter())
        .chain(tx_id_attr.iter())
        .chain(nonce_attr.iter())
        .copied()
        .collect();

    Ok(all)
}

/// Build a single CMS Attribute: SEQUENCE { OID, SET { values... } }.
fn build_attr(oid_value: &[u8], values: &[Vec<u8>]) -> Result<Vec<u8>> {
    let oid = der_oid(oid_value);
    let mut values_inner = Vec::new();
    for v in values {
        values_inner.extend_from_slice(v);
    }
    let values_set = der_set(&values_inner);
    let inner: Vec<u8> = oid.iter().chain(values_set.iter()).copied().collect();
    Ok(der_sequence(&inner))
}

/// Re-encode authenticated attributes as an explicit SET OF (for signing).
///
/// RFC 5652 §5.4: "The DER encoding of the SET OF authenticated attributes
/// is the input to the signature computation."
fn repack_as_set(attrs_inner: &[u8]) -> Vec<u8> {
    der_set(attrs_inner)
}

/// Build SignedData SEQUENCE (RFC 5652 §5.1).
fn build_signed_data_inner(
    payload: &[u8],
    auth_attrs: &[u8],
    signature: &[u8],
    requester_cert_der: &[u8],
    signer_key: &KeyPair,
) -> Result<Vec<u8>> {
    // version: CMSVersion = 1 (uses issuerAndSerialNumber for SignerIdentifier)
    let version = der_integer_u32(1);

    // digestAlgorithms: SET { AlgorithmIdentifier(sha256) }
    let sha256_alg = algorithm_identifier_with_null(OID_SHA256);
    let digest_algs = der_set(&sha256_alg);

    // encapContentInfo: SEQUENCE { id-data, [0] OCTET STRING(payload) }
    let eci = build_encap_content_info(payload);

    // certificates: [0] IMPLICIT SET (requester self-signed cert)
    let certs = build_certificates_field(requester_cert_der);

    // signerInfos: SET { SignerInfo }
    let signer_info = build_signer_info(auth_attrs, signature, requester_cert_der, signer_key)?;
    let signer_infos = der_set(&signer_info);

    let inner: Vec<u8> = version
        .iter()
        .chain(digest_algs.iter())
        .chain(eci.iter())
        .chain(certs.iter())
        .chain(signer_infos.iter())
        .copied()
        .collect();

    Ok(der_sequence(&inner))
}

/// Build EncapsulatedContentInfo SEQUENCE { id-data, \[0\] OCTET STRING(payload) }.
fn build_encap_content_info(payload: &[u8]) -> Vec<u8> {
    let oid = der_oid(OID_DATA);
    let payload_oct = der_octet_string(payload);
    let explicit = der_context_explicit(0, &payload_oct);
    let inner: Vec<u8> = oid.iter().chain(explicit.iter()).copied().collect();
    der_sequence(&inner)
}

/// Build the \[0\] IMPLICIT certificates field in SignedData.
fn build_certificates_field(cert_der: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa0]; // [0] CONSTRUCTED
    encode_length(&mut out, cert_der.len());
    out.extend_from_slice(cert_der);
    out
}

/// Build SignerInfo SEQUENCE (RFC 5652 §5.3).
fn build_signer_info(
    auth_attrs: &[u8],
    signature: &[u8],
    requester_cert_der: &[u8],
    signer_key: &KeyPair,
) -> Result<Vec<u8>> {
    // version: CMSVersion = 1 (issuerAndSerialNumber)
    let version = der_integer_u32(1);

    // sid: IssuerAndSerialNumber from requester cert
    let sid = extract_issuer_and_serial(requester_cert_der)
        .context("Failed to extract issuer and serial from requester cert")?;

    // digestAlgorithm: sha256
    let digest_alg = algorithm_identifier_with_null(OID_SHA256);

    // authenticatedAttributes: [0] IMPLICIT SET OF Attribute
    let mut auth_attrs_field = vec![0xa0]; // [0] CONSTRUCTED
    encode_length(&mut auth_attrs_field, auth_attrs.len());
    auth_attrs_field.extend_from_slice(auth_attrs);

    // signatureAlgorithm: AlgorithmIdentifier for signer_key
    let sig_alg = build_sig_algorithm_id(signer_key)?;

    // signature: OCTET STRING
    let sig_oct = der_octet_string(signature);

    let inner: Vec<u8> = version
        .iter()
        .chain(sid.iter())
        .chain(digest_alg.iter())
        .chain(auth_attrs_field.iter())
        .chain(sig_alg.iter())
        .chain(sig_oct.iter())
        .copied()
        .collect();

    Ok(der_sequence(&inner))
}

/// Build AlgorithmIdentifier for the signer key algorithm.
fn build_sig_algorithm_id(key: &KeyPair) -> Result<Vec<u8>> {
    match key.algorithm_id() {
        AlgorithmId::Rsa2048 | AlgorithmId::Rsa4096 | AlgorithmId::Rsa3072 => {
            // sha256WithRSAEncryption with NULL params
            Ok(algorithm_identifier_with_null(OID_SHA256_WITH_RSA))
        }
        AlgorithmId::EcdsaP256 | AlgorithmId::EcdsaP384 => {
            // ecdsaWithSHA256 — no params (RFC 5758)
            // OID 1.2.840.10045.4.3.2
            let ecdsa_sha256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
            Ok(algorithm_identifier_no_params(ecdsa_sha256))
        }
        _ => Err(anyhow!(
            "Unsupported key algorithm for SCEP: {}",
            key.algorithm_id()
        )),
    }
}

/// Extract IssuerAndSerialNumber DER from a certificate.
///
/// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber CertificateSerialNumber }
fn extract_issuer_and_serial(cert_der: &[u8]) -> Result<Vec<u8>> {
    // Parse the TBSCertificate from the cert DER to extract issuer and serial
    // Structure: SEQUENCE { SEQUENCE(TBS) { ... } }
    // TBSCertificate: SEQUENCE { version[0], serial INTEGER, signature AlgId, issuer Name, ... }
    let tbs = extract_tbs_cert(cert_der).context("Failed to extract TBSCertificate")?;

    let serial = extract_serial_from_tbs(tbs).context("Failed to extract serial")?;
    let issuer = extract_issuer_from_tbs(tbs).context("Failed to extract issuer")?;

    let inner: Vec<u8> = issuer.iter().chain(serial.iter()).copied().collect();
    Ok(der_sequence(&inner))
}

/// Extract TBSCertificate bytes (the inner SEQUENCE) from a Certificate DER.
fn extract_tbs_cert(cert_der: &[u8]) -> Result<&[u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, ... }
    let (inner, _) = parse_sequence(cert_der).context("Certificate is not a SEQUENCE")?;
    // First element of Certificate is TBSCertificate (a SEQUENCE)
    let (tbs, _) = parse_sequence(inner).context("TBSCertificate is not a SEQUENCE")?;
    Ok(tbs)
}

/// Extract the serial number DER bytes from TBSCertificate bytes.
fn extract_serial_from_tbs(tbs: &[u8]) -> Result<Vec<u8>> {
    // TBSCertificate: version[0] OPTIONAL, serial INTEGER, ...
    let mut pos = 0;

    // Skip optional [0] EXPLICIT version
    if pos < tbs.len() && tbs[pos] == 0xa0 {
        let (_, consumed) = parse_tlv(tbs)?;
        pos += consumed;
    }

    // serial INTEGER
    if pos >= tbs.len() || tbs[pos] != 0x02 {
        return Err(anyhow!("Expected INTEGER tag for serial"));
    }
    let (_, consumed) = parse_tlv(&tbs[pos..])?;
    Ok(tbs[pos..pos + consumed].to_vec())
}

/// Extract the issuer Name DER bytes from TBSCertificate bytes.
fn extract_issuer_from_tbs(tbs: &[u8]) -> Result<Vec<u8>> {
    let mut pos = 0;

    // Skip optional version [0]
    if pos < tbs.len() && tbs[pos] == 0xa0 {
        let (_, consumed) = parse_tlv(tbs)?;
        pos += consumed;
    }

    // Skip serial INTEGER
    let (_, serial_len) = parse_tlv(&tbs[pos..])?;
    pos += serial_len;

    // Skip signature AlgorithmIdentifier SEQUENCE
    let (_, sig_alg_len) = parse_tlv(&tbs[pos..])?;
    pos += sig_alg_len;

    // issuer Name (SEQUENCE)
    let (_, issuer_len) = parse_tlv(&tbs[pos..])?;
    Ok(tbs[pos..pos + issuer_len].to_vec())
}

// ── DER parsing helpers ───────────────────────────────────────────────────────

/// Parse a DER TLV and return `(contents_slice, total_bytes_consumed)`.
fn parse_tlv(data: &[u8]) -> Result<(&[u8], usize)> {
    if data.is_empty() {
        return Err(anyhow!("Empty DER input"));
    }
    let _tag = data[0];
    if data.len() < 2 {
        return Err(anyhow!("DER truncated after tag"));
    }
    let (len, header_len) = parse_der_length(&data[1..])?;
    let total = 1 + header_len + len;
    if data.len() < total {
        return Err(anyhow!(
            "DER truncated: need {} bytes, have {}",
            total,
            data.len()
        ));
    }
    Ok((&data[1 + header_len..total], total))
}

/// Parse a SEQUENCE and return `(contents_slice, total_bytes_consumed)`.
fn parse_sequence(data: &[u8]) -> Result<(&[u8], usize)> {
    if data.is_empty() || data[0] != 0x30 {
        return Err(anyhow!(
            "Expected SEQUENCE tag 0x30, got 0x{:02x}",
            data.first().copied().unwrap_or(0)
        ));
    }
    parse_tlv(data)
}

/// Parse DER length encoding. Returns `(length_value, bytes_consumed_by_length_field)`.
fn parse_der_length(data: &[u8]) -> Result<(usize, usize)> {
    if data.is_empty() {
        return Err(anyhow!("Empty DER length field"));
    }
    if data[0] < 0x80 {
        return Ok((data[0] as usize, 1));
    }
    let num_bytes = (data[0] & 0x7f) as usize;
    if num_bytes == 0 || num_bytes > 4 {
        return Err(anyhow!(
            "DER length: unsupported long form ({} bytes)",
            num_bytes
        ));
    }
    if data.len() < 1 + num_bytes {
        return Err(anyhow!("DER length: truncated"));
    }
    let mut len = 0usize;
    for i in 0..num_bytes {
        len = (len << 8) | data[1 + i] as usize;
    }
    Ok((len, 1 + num_bytes))
}

/// SCEP recipientNonce (2.16.840.1.113733.1.9.6)
pub(crate) const OID_SCEP_RECIPIENT_NONCE: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x06];
/// SCEP failInfo (2.16.840.1.113733.1.9.4)
pub(crate) const OID_SCEP_FAIL_INFO: &[u8] =
    &[0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x45, 0x01, 0x09, 0x04];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_short() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 0x7f);
        assert_eq!(buf, &[0x7f]);
    }

    #[test]
    fn test_encode_length_long() {
        let mut buf = Vec::new();
        encode_length(&mut buf, 256);
        assert_eq!(buf, &[0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_der_sequence() {
        let inner = &[0x01, 0x02];
        let seq = der_sequence(inner);
        assert_eq!(seq, &[0x30, 0x02, 0x01, 0x02]);
    }

    #[test]
    fn test_parse_tlv_roundtrip() {
        let seq = der_sequence(&[0x02, 0x01, 0x01]);
        let (contents, total) = parse_tlv(&seq).unwrap();
        assert_eq!(total, seq.len());
        assert_eq!(contents, &[0x02, 0x01, 0x01]);
    }

    #[test]
    fn test_build_message_material_rsa2048() {
        let mat = build_message_material(
            "test.example.com",
            Some("secret"),
            ScepKeyType::Rsa2048,
            &[],
        )
        .expect("Should build SCEP message material");

        assert!(!mat.csr_der.is_empty());
        assert!(!mat.requester_cert_der.is_empty());
        assert_eq!(mat.transaction_id.len(), 64); // 32-byte SHA-256 → 64 hex chars
        assert_eq!(mat.sender_nonce.len(), 16);
    }

    #[test]
    fn test_build_message_material_ec_p256() {
        let mat = build_message_material(
            "ec-test.example.com",
            None,
            ScepKeyType::EcP256,
            &["san.example.com".to_string()],
        )
        .expect("Should build SCEP message material for EC");

        assert!(!mat.csr_der.is_empty());
        assert!(!mat.requester_cert_der.is_empty());
    }

    #[test]
    fn test_key_type_from_str() {
        assert_eq!(
            "rsa2048".parse::<ScepKeyType>().unwrap(),
            ScepKeyType::Rsa2048
        );
        assert_eq!(
            "rsa4096".parse::<ScepKeyType>().unwrap(),
            ScepKeyType::Rsa4096
        );
        assert_eq!(
            "ec-p256".parse::<ScepKeyType>().unwrap(),
            ScepKeyType::EcP256
        );
        assert!("invalid".parse::<ScepKeyType>().is_err());
    }
}
