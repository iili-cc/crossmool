This package provides SM2/SM3/SM4 utilities compatible with the crossmool implementations in other languages.

Install:

```powershell
pip install gmssl
# then install this package (from package root)
pip install -e python/crossmool
```

Quick usage:

```py
from crossmool import SM2Util, SM3Util, SM4Util

# SM2 keypair (raw hex)
priv, pub = SM2Util.generate_keypair_raw()

# encrypt/sign
ct_hex = SM2Util.encrypt('hello', pub)
sig_hex = SM2Util.sign(ct_hex, priv)

# verify/decrypt
ok = SM2Util.verify_str(ct_hex, pub, sig_hex)
pt = SM2Util.decrypt(ct_hex, priv)

print(ok, pt)
```
