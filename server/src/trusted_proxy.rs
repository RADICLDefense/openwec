use anyhow::{bail, Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use hyper::header::HeaderName;
use hyper::Request;
use openssl::stack::Stack;
use openssl::x509::store::X509StoreBuilder;
use openssl::x509::{X509StoreContext, X509};
use percent_encoding::percent_decode_str;
use std::collections::HashMap;
use std::net::IpAddr;

use crate::tls::{compute_thumbprint, issuer_from_cert, load_certs, subject_from_cert};

#[derive(Debug, Clone)]
pub struct TrustedProxyConfig {
    client_certificate_header: HeaderName,
    client_certificate_subject_header: HeaderName,
    client_certificate_issuer_header: HeaderName,
    client_certificate_serial_header: HeaderName,
    client_certificate_validity_header: HeaderName,
    x_forwarded_for_header: HeaderName,
    ca_certs: Vec<X509>,
    ca_thumbprints: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedProxyAuth {
    pub subject: String,
    pub thumbprint: String,
    pub client_ip: Option<IpAddr>,
}

pub fn make_config(args: &common::settings::TrustedProxyTls) -> Result<TrustedProxyConfig> {
    let ca_certs = load_certs(args.ca_certificate()).context("Could not load CA certificate")?;
    if ca_certs.is_empty() {
        bail!("CA certificate should contain at least one certificate");
    }

    let mut trusted_cas = Vec::with_capacity(ca_certs.len());
    let mut ca_thumbprints = HashMap::new();
    for ca_cert in ca_certs {
        let subject = subject_from_cert(ca_cert.as_ref())?;
        let thumbprint = compute_thumbprint(ca_cert.as_ref());
        if let Some(existing) = ca_thumbprints.get(&subject) {
            if existing != &thumbprint {
                bail!(
                    "Duplicate CA subject with different thumbprints: {}",
                    &subject
                );
            }
            continue;
        }
        ca_thumbprints.insert(subject, thumbprint);
        trusted_cas.push(X509::from_der(ca_cert.as_ref()).context("Could not parse CA cert")?);
    }

    Ok(TrustedProxyConfig {
        client_certificate_header: parse_header_name(
            args.client_certificate_header(),
            "client_certificate_header",
        )?,
        client_certificate_subject_header: parse_header_name(
            args.client_certificate_subject_header(),
            "client_certificate_subject_header",
        )?,
        client_certificate_issuer_header: parse_header_name(
            args.client_certificate_issuer_header(),
            "client_certificate_issuer_header",
        )?,
        client_certificate_serial_header: parse_header_name(
            args.client_certificate_serial_header(),
            "client_certificate_serial_header",
        )?,
        client_certificate_validity_header: parse_header_name(
            args.client_certificate_validity_header(),
            "client_certificate_validity_header",
        )?,
        x_forwarded_for_header: parse_header_name(
            args.x_forwarded_for_header(),
            "x_forwarded_for_header",
        )?,
        ca_certs: trusted_cas,
        ca_thumbprints,
    })
}

pub fn authenticate_request<B>(
    config: &TrustedProxyConfig,
    req: &Request<B>,
) -> Result<TrustedProxyAuth> {
    let client_certificate_pem = get_required_header(req, &config.client_certificate_header)?;
    let client_certificate_subject =
        get_optional_header(req, &config.client_certificate_subject_header)?;
    let client_certificate_issuer =
        get_optional_header(req, &config.client_certificate_issuer_header)?;
    let client_certificate_serial =
        get_optional_header(req, &config.client_certificate_serial_header)?;
    let client_certificate_validity =
        get_optional_header(req, &config.client_certificate_validity_header)?;
    let client_ip = get_forwarded_client_ip(req, &config.x_forwarded_for_header)?;

    let decoded_client_certificate = percent_decode_str(&client_certificate_pem)
        .decode_utf8()
        .context("Could not decode forwarded client certificate header")?;
    let client_certificate = X509::from_pem(decoded_client_certificate.as_bytes())
        .context("Could not parse forwarded client certificate")?;

    verify_certificate(&client_certificate, &config.ca_certs)?;

    let cert_der = client_certificate
        .to_der()
        .context("Could not serialize forwarded client certificate")?;
    let subject = subject_from_cert(&cert_der)
        .context("Could not parse subject from forwarded client certificate")?;
    let issuer = issuer_from_cert(&cert_der)
        .context("Could not parse issuer from forwarded client certificate")?;

    if let Some(client_certificate_subject) = client_certificate_subject.as_deref() {
        ensure_header_matches_common_name(
            client_certificate_subject,
            "client certificate subject",
            &subject,
        )?;
    }
    if let Some(client_certificate_issuer) = client_certificate_issuer.as_deref() {
        ensure_header_matches_common_name(
            client_certificate_issuer,
            "client certificate issuer",
            &issuer,
        )?;
    }

    let serial = client_certificate
        .serial_number()
        .to_bn()
        .context("Could not parse client certificate serial")?
        .to_hex_str()
        .context("Could not stringify client certificate serial")?
        .to_string();
    if let Some(client_certificate_serial) = client_certificate_serial.as_deref() {
        if normalize_hex(client_certificate_serial) != normalize_hex(&serial) {
            bail!("Forwarded client certificate serial header does not match certificate contents");
        }
    }

    let validity = format!(
        "NotBefore={};NotAfter={}",
        asn1_time_to_iso8601(client_certificate.not_before())?,
        asn1_time_to_iso8601(client_certificate.not_after())?
    );
    if let Some(client_certificate_validity) = client_certificate_validity.as_deref() {
        if client_certificate_validity != validity {
            bail!(
                "Forwarded client certificate validity header does not match certificate contents"
            );
        }
    }

    let thumbprint = config
        .ca_thumbprints
        .get(&issuer)
        .cloned()
        .context("No trusted CA found for forwarded client certificate issuer")?;

    Ok(TrustedProxyAuth {
        subject,
        thumbprint,
        client_ip,
    })
}

fn parse_header_name(header: &str, field_name: &str) -> Result<HeaderName> {
    header
        .parse::<HeaderName>()
        .with_context(|| format!("Invalid value for {}", field_name))
}

fn get_required_header<B>(req: &Request<B>, header: &HeaderName) -> Result<String> {
    req.headers()
        .get(header)
        .context(format!("Missing required header {:?}", header))?
        .to_str()
        .context(format!("Header {:?} is not valid UTF-8", header))
        .map(|value| value.to_string())
}

fn get_optional_header<B>(req: &Request<B>, header: &HeaderName) -> Result<Option<String>> {
    req.headers()
        .get(header)
        .map(|value| {
            value
                .to_str()
                .context(format!("Header {:?} is not valid UTF-8", header))
                .map(|value| value.to_string())
        })
        .transpose()
}

fn get_forwarded_client_ip<B>(req: &Request<B>, header: &HeaderName) -> Result<Option<IpAddr>> {
    match get_optional_header(req, header)? {
        Some(forwarded_for) => parse_forwarded_for_value(&forwarded_for).map(Some),
        None => Ok(None),
    }
}

fn parse_forwarded_for_value(forwarded_for: &str) -> Result<IpAddr> {
    let rightmost_hop = forwarded_for
        .split(',')
        .map(str::trim)
        .rev()
        .find(|value| !value.is_empty())
        .context("Forwarded client IP header is empty")?;

    if let Ok(ip) = rightmost_hop.parse::<IpAddr>() {
        return Ok(ip);
    }

    if let Ok(socket_addr) = rightmost_hop.parse::<std::net::SocketAddr>() {
        return Ok(socket_addr.ip());
    }

    bail!("Forwarded client IP header does not contain a valid IP address")
}

fn verify_certificate(cert: &X509, ca_certs: &[X509]) -> Result<()> {
    let mut store_builder = X509StoreBuilder::new().context("Could not create X509 store")?;
    for ca_cert in ca_certs {
        store_builder
            .add_cert(ca_cert.clone())
            .context("Could not add CA certificate to X509 store")?;
    }
    let store = store_builder.build();

    let chain = Stack::new().context("Could not create X509 chain stack")?;
    let mut store_context =
        X509StoreContext::new().context("Could not create X509 store context")?;
    let verified = store_context
        .init(&store, cert, &chain, |context| context.verify_cert())
        .context("Could not verify forwarded client certificate")?;

    if !verified {
        bail!("Forwarded client certificate is not trusted");
    }
    Ok(())
}

fn ensure_header_matches_common_name(
    header_value: &str,
    header_name: &str,
    common_name: &str,
) -> Result<()> {
    let expected_component = format!("CN={}", common_name);
    if header_value
        .split(',')
        .any(|component| component.trim() == expected_component)
    {
        Ok(())
    } else {
        bail!(
            "Forwarded {} header does not match certificate common name",
            header_name
        )
    }
}

fn normalize_hex(value: &str) -> String {
    let trimmed = value.trim_start_matches('0');
    if trimmed.is_empty() {
        "0".to_string()
    } else {
        trimmed.to_uppercase()
    }
}

fn asn1_time_to_iso8601(time: &openssl::asn1::Asn1TimeRef) -> Result<String> {
    let timestamp = NaiveDateTime::parse_from_str(&time.to_string(), "%b %e %H:%M:%S %Y GMT")
        .context("Could not parse certificate timestamp")?;
    Ok(DateTime::<Utc>::from_naive_utc_and_offset(timestamp, Utc)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::settings::{Authentication, Settings};
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::nid::Nid;
    use openssl::pkey::{PKey, Private};
    use openssl::rsa::Rsa;
    use openssl::x509::extension::{
        AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
    };
    use openssl::x509::{X509Builder, X509NameBuilder};
    use percent_encoding::{utf8_percent_encode, NON_ALPHANUMERIC};
    use std::net::{IpAddr, Ipv4Addr};
    use std::str::FromStr;

    fn test_config(ca_cert_path: &str) -> TrustedProxyConfig {
        let settings = Settings::from_str(&format!(
            r#"
                [database]
                type = "SQLite"
                path = "/tmp/openwec.sqlite"

                [[collectors]]
                listen_address = "127.0.0.1"

                [collectors.authentication]
                type = "TrustedProxyTls"
                ca_certificate = "{ca_cert_path}"
                client_certificate_header = "x-amzn-mtls-clientcert-leaf"
                client_certificate_subject_header = "x-amzn-mtls-clientcert-subject"
                client_certificate_issuer_header = "x-amzn-mtls-clientcert-issuer"
                client_certificate_serial_header = "x-amzn-mtls-clientcert-serial-number"
                client_certificate_validity_header = "x-amzn-mtls-clientcert-validity"
            "#
        ))
        .unwrap();

        let trusted_proxy = match settings.collectors()[0].authentication() {
            Authentication::TrustedProxyTls(trusted_proxy) => trusted_proxy,
            _ => panic!("Wrong authentication type"),
        };

        make_config(trusted_proxy).unwrap()
    }

    fn generate_ca(common_name: &str) -> (PKey<Private>, X509) {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(1).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(365).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(None, None))
            .unwrap();
        builder.append_extension(subject_key_identifier).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();

        (key, builder.build())
    }

    fn generate_leaf(ca_key: &PKey<Private>, ca_cert: &X509, common_name: &str) -> X509 {
        let rsa = Rsa::generate(2048).unwrap();
        let key = PKey::from_rsa(rsa).unwrap();

        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, common_name)
            .unwrap();
        let name = name.build();

        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        let serial = BigNum::from_u32(42).unwrap().to_asn1_integer().unwrap();
        builder.set_serial_number(&serial).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::days_from_now(30).unwrap())
            .unwrap();
        builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        builder
            .append_extension(
                KeyUsage::new()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let authority_key_identifier = AuthorityKeyIdentifier::new()
            .keyid(true)
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        builder.append_extension(authority_key_identifier).unwrap();
        let subject_key_identifier = SubjectKeyIdentifier::new()
            .build(&builder.x509v3_context(Some(ca_cert), None))
            .unwrap();
        builder.append_extension(subject_key_identifier).unwrap();
        builder.sign(ca_key, MessageDigest::sha256()).unwrap();

        builder.build()
    }

    fn write_cert(path: &std::path::Path, cert: &X509) {
        std::fs::write(path, cert.to_pem().unwrap()).unwrap();
    }

    fn validity_header(cert: &X509) -> String {
        format!(
            "NotBefore={};NotAfter={}",
            asn1_time_to_iso8601(cert.not_before()).unwrap(),
            asn1_time_to_iso8601(cert.not_after()).unwrap()
        )
    }

    fn serial_header(cert: &X509) -> String {
        cert.serial_number()
            .to_bn()
            .unwrap()
            .to_hex_str()
            .unwrap()
            .to_string()
    }

    fn encoded_leaf_header(cert: &X509) -> String {
        utf8_percent_encode(
            std::str::from_utf8(&cert.to_pem().unwrap()).unwrap(),
            NON_ALPHANUMERIC,
        )
        .to_string()
    }

    #[test]
    fn test_authenticate_request() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-amzn-mtls-clientcert-subject", "CN=client-01")
            .header("x-amzn-mtls-clientcert-issuer", "CN=trusted-ca")
            .header(
                "x-amzn-mtls-clientcert-serial-number",
                serial_header(&leaf_cert),
            )
            .header(
                "x-amzn-mtls-clientcert-validity",
                validity_header(&leaf_cert),
            )
            .header("x-forwarded-for", "198.51.100.24, 10.0.0.10")
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(auth.subject, "client-01");
        assert_eq!(
            auth.thumbprint,
            compute_thumbprint(&ca_cert.to_der().unwrap())
        );
        assert_eq!(
            auth.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 10)))
        );
    }

    #[test]
    fn test_authenticate_request_rejects_missing_header() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (_ca_key, ca_cert) = generate_ca("trusted-ca");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder().body(()).unwrap();

        let err = authenticate_request(&config, &req).unwrap_err();
        assert!(err
            .to_string()
            .contains("Missing required header \"x-amzn-mtls-clientcert-leaf\""));
    }

    #[test]
    fn test_authenticate_request_rejects_subject_mismatch() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-amzn-mtls-clientcert-subject", "CN=other-client")
            .header("x-amzn-mtls-clientcert-issuer", "CN=trusted-ca")
            .header(
                "x-amzn-mtls-clientcert-serial-number",
                serial_header(&leaf_cert),
            )
            .header(
                "x-amzn-mtls-clientcert-validity",
                validity_header(&leaf_cert),
            )
            .header("x-forwarded-for", "198.51.100.24")
            .body(())
            .unwrap();

        let err = authenticate_request(&config, &req).unwrap_err();
        assert!(err
            .to_string()
            .contains("Forwarded client certificate subject header does not match"));
    }

    #[test]
    fn test_authenticate_request_rejects_untrusted_cert() {
        let tempdir = tempfile::tempdir().unwrap();
        let trusted_ca_path = tempdir.path().join("trusted-ca.pem");
        let (trusted_ca_key, trusted_ca_cert) = generate_ca("trusted-ca");
        let (other_ca_key, other_ca_cert) = generate_ca("other-ca");
        let leaf_cert = generate_leaf(&other_ca_key, &other_ca_cert, "client-01");
        let _ = trusted_ca_key;
        write_cert(&trusted_ca_path, &trusted_ca_cert);

        let config = test_config(trusted_ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-amzn-mtls-clientcert-subject", "CN=client-01")
            .header("x-amzn-mtls-clientcert-issuer", "CN=other-ca")
            .header(
                "x-amzn-mtls-clientcert-serial-number",
                serial_header(&leaf_cert),
            )
            .header(
                "x-amzn-mtls-clientcert-validity",
                validity_header(&leaf_cert),
            )
            .header("x-forwarded-for", "198.51.100.24")
            .body(())
            .unwrap();

        let err = authenticate_request(&config, &req).unwrap_err();
        let err_string = err.to_string();
        assert!(
            err_string.contains("Could not verify forwarded client certificate")
                || err_string.contains("Forwarded client certificate is not trusted")
        );
    }

    #[test]
    fn test_authenticate_request_allows_missing_metadata_headers() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(auth.subject, "client-01");
        assert_eq!(auth.client_ip, None);
    }

    #[test]
    fn test_authenticate_request_allows_missing_forwarded_ip() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-amzn-mtls-clientcert-subject", "CN=client-01")
            .header("x-amzn-mtls-clientcert-issuer", "CN=trusted-ca")
            .header(
                "x-amzn-mtls-clientcert-serial-number",
                serial_header(&leaf_cert),
            )
            .header(
                "x-amzn-mtls-clientcert-validity",
                validity_header(&leaf_cert),
            )
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(auth.client_ip, None);
    }

    #[test]
    fn test_authenticate_request_supports_custom_forwarded_ip_header() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let settings = Settings::from_str(&format!(
            r#"
                [database]
                type = "SQLite"
                path = "/tmp/openwec.sqlite"

                [[collectors]]
                listen_address = "127.0.0.1"

                [collectors.authentication]
                type = "TrustedProxyTls"
                ca_certificate = "{}"
                x_forwarded_for_header = "x-real-ip"
            "#,
            ca_path.display()
        ))
        .unwrap();

        let trusted_proxy = match settings.collectors()[0].authentication() {
            Authentication::TrustedProxyTls(trusted_proxy) => trusted_proxy,
            _ => panic!("Wrong authentication type"),
        };
        let config = make_config(trusted_proxy).unwrap();

        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-amzn-mtls-clientcert-subject", "CN=client-01")
            .header("x-amzn-mtls-clientcert-issuer", "CN=trusted-ca")
            .header(
                "x-amzn-mtls-clientcert-serial-number",
                serial_header(&leaf_cert),
            )
            .header(
                "x-amzn-mtls-clientcert-validity",
                validity_header(&leaf_cert),
            )
            .header("x-real-ip", "198.51.100.24")
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(
            auth.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)))
        );
    }

    #[test]
    fn test_authenticate_request_uses_rightmost_forwarded_ip() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-forwarded-for", "203.0.113.10, 198.51.100.24")
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(
            auth.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)))
        );
    }

    #[test]
    fn test_authenticate_request_uses_rightmost_forwarded_ip_with_multiple_hops() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header(
                "x-forwarded-for",
                "203.0.113.10, 198.51.100.77, 198.51.100.24",
            )
            .body(())
            .unwrap();

        let auth = authenticate_request(&config, &req).unwrap();
        assert_eq!(
            auth.client_ip,
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)))
        );
    }

    #[test]
    fn test_authenticate_request_rejects_invalid_forwarded_ip_when_present() {
        let tempdir = tempfile::tempdir().unwrap();
        let ca_path = tempdir.path().join("ca.pem");
        let (ca_key, ca_cert) = generate_ca("trusted-ca");
        let leaf_cert = generate_leaf(&ca_key, &ca_cert, "client-01");
        write_cert(&ca_path, &ca_cert);

        let config = test_config(ca_path.to_str().unwrap());
        let req = Request::builder()
            .header(
                "x-amzn-mtls-clientcert-leaf",
                encoded_leaf_header(&leaf_cert),
            )
            .header("x-forwarded-for", "not-an-ip")
            .body(())
            .unwrap();

        let err = authenticate_request(&config, &req).unwrap_err();
        assert!(err
            .to_string()
            .contains("Forwarded client IP header does not contain a valid IP address"));
    }

    #[test]
    fn test_parse_forwarded_for_value_with_client_port() {
        let ip = parse_forwarded_for_value("198.51.100.24:12345").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
    }

    #[test]
    fn test_parse_forwarded_for_value_uses_rightmost_ip() {
        let ip = parse_forwarded_for_value("203.0.113.10, 198.51.100.24").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
    }

    #[test]
    fn test_parse_forwarded_for_value_uses_rightmost_socket_addr() {
        let ip = parse_forwarded_for_value("203.0.113.10, 198.51.100.24:12345").unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(198, 51, 100, 24)));
    }
}
