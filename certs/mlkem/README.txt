ML-KEM (FIPS 203) test key material for wolfSSL tests.

Per level N in {512, 768, 1024}:
  mlkem<N>-cert.der   ML-KEM end-entity certificate, DER
  mlkem<N>-key.der    matching private key, PKCS#8 DER (expanded form)

A KEM cannot sign, so these certificates cannot be self-signed. Each is
issued by the ML-DSA-87 test key in certs/mldsa, so certs/mldsa/mldsa87-cert.der
is the issuer and certs/mldsa/mldsa87-key.der signed them.

The certificates follow the CNSA 2.0 profile for a key establishment
certificate: the keyUsage extension is marked critical and asserts
keyEncipherment alone. The subjectPublicKeyInfo algorithm is
2.16.840.1.101.3.4.4.N with the parameters field absent, and the signature
algorithm is 2.16.840.1.101.3.4.3.19 (ML-DSA-87).

These were generated in tree, because ML-KEM certificate issuance is not
available in OpenSSL before 3.5. gen_mlkem.c in this directory regenerates
them. Build wolfSSL with

  ./configure --enable-mldsa --enable-mlkem --enable-keygen \
              --enable-certgen --enable-certreq --enable-certext

install it, then

  cc gen_mlkem.c -lwolfssl -o gen_mlkem && (cd certs/mlkem && ./gen_mlkem)

It reads ../mldsa/mldsa87-cert.der and ../mldsa/mldsa87-key.der as the issuer
and writes one certificate and key per enabled parameter set. The keys are
freshly generated, so the output differs from the committed files on every run;
only the structure is reproducible, not the bytes.

These are shared test credentials. Never use them in production.
