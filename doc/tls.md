# Configuration for TLS authentication

> [!caution]
> This feature is **EXPERIMENTAL**, please use carefully. There are known issues with our TLS implementation (see #291).

This documentation describes how to set up TLS authentication. Certificates need to be generated first, then follow the rest of the documentation in parallel with [getting_started.md](getting_started.md/#configuring-windows-machines).

## Certificates

**The following certificates are needed**:
- A certificate for the server, with extensions Server Authentication and PKIs,
- A certificate for the client, with extensions Client Authentication and PKIs,
- A certificate of the CA that signed the client certificate and the server certificate (they can be distinct).

**Requirements for the Windows client**:
- It needs to support TLS 1.2 or TLS 1.3 (this includes Windows servers from 2012 and Windows 8).

For older versions of Windows, TLS 1.2 needs to be available at least. At least one of the following cipher suites has to be available:
- TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
- TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
- TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256

For more recent versions using TLS 1.3, at least one of the following cipher suites has to be available for it to be used:
- TLS13_AES_256_GCM_SHA384
- TLS13_AES_128_GCM_SHA256
- TLS13_CHACHA20_POLY1305_SHA256

You can find the currently available suites of a Windows machine in: *Local Group Policy Editor > Computer Configuration > Administrative Templates > Network > SSL Configuration Settings* (cf. [this page](https://learn.microsoft.com/en-us/windows/win32/secauthn/cipher-suites-in-schannel) for more precisions).

**Requirements for the certificates and keys**:
- Certificate and key files must be in PEM format
- Server FQDN must be used as `CommonName` of server certificate
- `CommonName` of client certificate must be unique and should be distinguishable (they are used to display connections and as authenticated name in the logs)

Keys must be encoded using either RSA PKCS#1 (cf. RFC3447), PKCS#8 (cf. RFC5958) or Sec-1 (cf. RFC5915).

Only the following curves are supported:
- ecdsa_secp256r1_sha256 (also called prime256v1)
- ecdsa_secp384r1_sha384
<!-- - ed25519: this should work but can't import in windows ? / openssl genpkey -algorithm ed25519 -out private.pem -->

You can find the currently available elliptic curves of a Windows machine with the command: `certutil.exe –displayEccCurve`.

If the clients are only composed of recent Windows machines (more recent than Windows server 2012 R2 and Windows 8), [nxlog's scripts](https://gitlab.com/nxlog-public/contrib/-/tree/master/windows-event-forwarding) should work just fine for certificate generation, while modifying the subjects and making sure they follow the rules detailed before.

It seems that older versions (particularly Windows Server 2012 R2) tend to support only TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 and
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. Certificates that are supported in this case can be created using the following (and largely inspired by the formely-mentioned) example script:

```sh
#!/bin/bash
# Usage:  `script <ca-FQDN> <server-FQDN> <client-FQDN> [<curve>]`
# Don't forget to modify "O=example.local/C=HU/ST=state/L=location" with relevant values as well
# Curve can only be 'secp384r1' or 'secp256r1', by default it will be assumed as being 'secp384r1'

# by default, curve is secp384r1
if [[ -z "$4" || "$4" != "secp256r1" ]]
then CURVE="secp384r1"
else CURVE="secp256r1"
fi

# CA certificate
CA_NAME="$1"
SUBJ="/CN=$CA_NAME/O=example.local/C=HU/ST=state/L=location"
openssl ecparam -out ca-key.pem -name $CURVE -genkey
openssl req -x509 -nodes -key ca-key.pem -out ca-cert.pem -batch -subj "$SUBJ" -config gencert.cnf

# Server certificate
SERVERNAME="$2"
ISSUERCA=`openssl x509 -in ca-cert.pem -noout -sha1 -fingerprint |sed s/^SHA1\ Fingerprint=//i|sed s/://g`
SERVERSUBJ="/CN=$SERVERNAME/O=example.local/C=HU/ST=state/L=location"
CERTDIR=.
openssl ecparam -out server-key.pem -name $CURVE -genkey
openssl req -new -key server-key.pem -out req.pem -batch -subj "$SERVERSUBJ" -config gencert.cnf
openssl x509 -req -days 1024 -in req.pem -CA ca-cert.pem -CAkey ca-key.pem -out server-cert.pem -set_serial 01 -extensions server_cert -extfile gencert.cnf
rm -f req.pem
openssl x509 -outform der -in server-cert.pem -out server-cert.crt
echo "###############################################################"
echo "Use the following for the Subscription Manager string:"
echo "Server=HTTPS://$SERVERNAME:5986/wsman/,Refresh=14400,IssuerCA=$ISSUERCA"

# Client certificate
CLIENTNAME="$3"
CLIENTSUBJ="/CN=$CLIENTNAME/O=example.local/C=HU/ST=state/L=location"
openssl ecparam -out client-key.pem -name $CURVE -genkey
openssl req -new -key client-key.pem -out req.pem -batch -subj "$CLIENTSUBJ" -config gencert.cnf
openssl x509 -req -days 1024 -in req.pem -CA ca-cert.pem -CAkey ca-key.pem -out client-cert.pem -set_serial 01 -extensions client_cert -extfile gencert.cnf
rm -f req.pem
openssl pkcs12 -export -out client.pfx -inkey client-key.pem -in client-cert.pem -certfile ca-cert.pem
```

The content of `gencert.cnf` used for this script can be found [here](https://gitlab.com/nxlog-public/contrib/-/blob/master/windows-event-forwarding/gencert.cnf).

## Client configuration

Once all certificates are generated, the service can finally be setup. [Windows' manual](https://learn.microsoft.com/en-us/windows/win32/wec/setting-up-a-source-initiated-subscription#event-source-computer-configuration) is a good reference for this part of the configuration:

1. Install the client certificate on the Windows machine in the category `Personal` (from the certificate manager, right-click on a category and go to *All Tasks > Import...*, make sure to check the box next to "Include all extended properties")
2. Install the CA certificate (for the CA that signed the server certificate) in category `Trusted Root Certification Authorities`
3. Give `Network Service` the right to read the client certificate's private key (from the certificate manager, right-click on the client certificate and go to *Manage Private Keys*)
4. Modify local policy for event forwarding with the Subscription Manager string obtained when generating the certificates

Make sure to follow [the Getting Started page](getting_started.md/#configuring-windows-machines) as well for generic instructions.

If the client works on an older version of Windows, make sure to activate TLS 1.2 as explained [here](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/security/enable-tls-1-2-client#bkmk_protocol).
(Some other references: [Enable TLS 1.1 and 1.2](https://support.microsoft.com/en-us/topic/update-to-enable-tls-1-1-and-tls-1-2-as-default-secure-protocols-in-winhttp-in-windows-c4bd73d2-31d7-761e-0178-11268bb10392) and [TLS/SSL Settings](https://learn.microsoft.com/fr-fr/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn786418(v=ws.11)?redirectedfrom=MSDN)).

For troubleshooting, Windows Events from `Eventlog-ForwardingPlugin` (Operational) and `Windows Remote Management` (Analytics, needs to be enabled in the View drop-down) can be of great help.

## Server configuration

OpenWEC now supports two TLS-based collector modes:

- `Tls`: OpenWEC terminates TLS itself and requires a server certificate and private key.
- `TrustedProxyTls`: a trusted reverse proxy or load balancer terminates HTTPS and mTLS, then forwards the verified client certificate details to OpenWEC over HTTP.

### End-to-end TLS mode

To configure OpenWEC on a machine named `wec.winserver.local`, the minimal options to configure in `/etc/openwec.conf.toml` are as follows:

```toml
# /etc/openwec.conf.toml
[[collectors]]
hostname = "wec.winserver.local"

[collectors.authentication]
type = "Tls"
ca_certificate = "/etc/ca-cert.pem"
server_certificate = "/etc/server-cert.pem"
server_private_key = "/etc/server-key.pem"
```

### Trusted proxy TLS mode

Use `TrustedProxyTls` when HTTPS and mTLS are terminated by a trusted proxy in front of OpenWEC, such as an AWS Application Load Balancer configured for mTLS verification mode.

In this mode:

- OpenWEC does **not** require `server_certificate` or `server_private_key`.
- OpenWEC still requires the client CA bundle so that it can validate the forwarded client certificate.
- OpenWEC authenticates clients from the forwarded leaf certificate header and derives the client identity from that certificate.
- If optional forwarded subject or issuer headers are present, OpenWEC checks them for CN consistency against the forwarded certificate. Optional serial and validity headers are checked against the exact certificate values.
- If the forwarded client IP header is missing, OpenWEC falls back to the backend socket address.
- If the forwarded client IP header contains multiple comma-separated hops, OpenWEC uses the rightmost non-empty value as the effective client IP, which matches AWS ALB append behavior.

Operational notes:

- The OpenWEC backend listener should only be reachable from the trusted proxy or load balancer. In `TrustedProxyTls` mode, forwarded authentication headers are only trustworthy when that network boundary is enforced.
- The `ca_certificate` bundle may need to include the issuing chain material required to validate the forwarded leaf certificate. In simple direct-root deployments a root CA may be enough, but intermediate-based PKI deployments can require the relevant intermediates to be present in the configured bundle.

Minimal example:

```toml
# /etc/openwec.conf.toml
[[collectors]]
hostname = "wec.winserver.local"
listen_address = "0.0.0.0"

[collectors.authentication]
type = "TrustedProxyTls"
ca_certificate = "/etc/ca-cert.pem"
```

Default proxy header names are:

- `client_certificate_header`: `x-amzn-mtls-clientcert-leaf`
- `client_certificate_subject_header`: `x-amzn-mtls-clientcert-subject`
- `client_certificate_issuer_header`: `x-amzn-mtls-clientcert-issuer`
- `client_certificate_serial_header`: `x-amzn-mtls-clientcert-serial-number`
- `client_certificate_validity_header`: `x-amzn-mtls-clientcert-validity`
- `x_forwarded_for_header`: `x-forwarded-for`

Only the forwarded leaf certificate header is required at runtime. The subject and issuer headers are optional CN consistency checks, while the serial and validity headers are optional exact consistency checks. If the forwarded IP header is present, OpenWEC uses it as the client IP for event metadata and output path mapping; when that header contains multiple comma-separated hops, OpenWEC uses the rightmost non-empty value. Otherwise it falls back to the proxy-to-backend socket address. The `ca_certificate` bundle should contain whatever issuer certificates are needed for OpenWEC to validate the forwarded leaf certificate in your PKI.

See [openwec.conf.sample.toml](../openwec.conf.sample.toml) for the full list of available parameters and header overrides.

## Sharing a TLS certificate across machines

A common deployment pattern is to issue a single client TLS certificate per tenant and provision that certificate on every machine of that tenant. With the default `Subject` identity strategy, every machine in such a tenant collapses to the same client identifier, which means they share a bookmark, share heartbeats and share per-machine metrics.

If that is your situation, configure the affected subscription(s) with `client_identity_strategy = "SubjectAndMachineID"`. OpenWEC will then key bookmarks, heartbeats and metrics on the certificate subject *and* the SOAP `MachineID` advertised by the client, giving you per-machine granularity while still scoping data to the certificate's tenant.

See [Per-machine identity strategy](subscription.md#per-machine-identity-strategy) for the trade-offs and a step-by-step migration recipe.
