# crossmool

Cross-language SM2/SM3/SM4 cryptographic utilities. The Python implementation is fully interoperable with the Java/Go/Rust/C/C++/C#/JavaScript implementations in the [crossmool](https://gitee.com/iilic/crossmool) project.

## Features

- **SM2** — asymmetric encryption/decryption and signature (C1C3C2 ciphertext, X.509 / PKCS#8 DER keys, DER signatures).
- **SM3** — hash and HMAC-SM3.
- **SM4** — symmetric GCM encryption/decryption.
- Hex and Base64 encodings supported throughout.
- Guaranteed cross-language interop (simplified Chinese, traditional Chinese and English Unicode input).

## Installation

```bash
pip install crossmool
```

Requires Python 3.8+.

## Quick start

### SM2 — encrypt / decrypt / sign / verify

```python
from crossmool import SM2Util

priv, pub = SM2Util.generate_keypair_raw()

# encrypt then decrypt (Hex)
cipher = SM2Util.encrypt('hello', pub)
assert SM2Util.decrypt(cipher, priv) == 'hello'

# sign then verify
sig = SM2Util.sign(cipher, priv)
assert SM2Util.verify_str(cipher, pub, sig)
```

### SM3 — hash / HMAC

```python
from crossmool import SM3Util

digest = SM3Util.digest_str('hello 国密')
key = SM3Util.generate_hmac_key_to_str()
mac = SM3Util.hmac_str('hello 国密', key)
assert SM3Util.hmac_verify('hello 国密', key, mac)
```

### SM4 — GCM encrypt / decrypt

```python
from crossmool import SM4Util

key = SM4Util.generate_key()
cipher = SM4Util.encrypt_gcm_string(key, 'hello 国密')
plain = SM4Util.decrypt_gcm_to_string(key, cipher)
assert plain == 'hello 国密'
```

## Development

Editable install for development:

```bash
cd <repo-root>
pip install -e python/crossmool
```

Run the test suite:

```bash
cd python/crossmool
pytest -q
```

## License

LGPL-v3. See the [LICENSE](https://gitee.com/iilic/crossmool) file for details.
