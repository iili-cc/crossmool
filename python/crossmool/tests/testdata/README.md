These files are sample keys taken from the Java test output (for interoperability verification).

- `java_sample_public.spki.der.b64` and `.hex`: SubjectPublicKeyInfo (SPKI) encoded public key in Base64 and Hex.
- `java_sample_private.pkcs8.der.b64` and `.hex`: PKCS#8 encoded private key in Base64 and Hex.

You can use the Base64 files by decoding and loading via Java `KeyFactory` or use the hex forms after hex decoding.
