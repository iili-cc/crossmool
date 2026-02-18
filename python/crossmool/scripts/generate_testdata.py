import os
import sys
import sys
# ensure src is on path so we can import the package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))
from crossmool import SM2Util

out_dir = os.path.join(r'd:/workspaces/git/corssmool/crossmool/python/crossmool/tests', 'testdata')
os.makedirs(out_dir, exist_ok=True)

pub_spki, priv_pkcs8 = SM2Util.generate_keypair_asn1_bytes()
open(os.path.join(out_dir, 'public.spki.der'), 'wb').write(pub_spki)
open(os.path.join(out_dir, 'private.pkcs8.der'), 'wb').write(priv_pkcs8)

pub_b64, priv_b64 = SM2Util.generate_keypair_base64()
open(os.path.join(out_dir, 'public.spki.der.b64'), 'w').write(pub_b64)
open(os.path.join(out_dir, 'private.pkcs8.der.b64'), 'w').write(priv_b64)

pub_hex_a, priv_hex_a = SM2Util.generate_keypair_hex()
open(os.path.join(out_dir, 'public.spki.der.hex'), 'w').write(pub_hex_a)
open(os.path.join(out_dir, 'private.pkcs8.der.hex'), 'w').write(priv_hex_a)

priv_raw, pub_raw = SM2Util.generate_keypair_raw()
open(os.path.join(out_dir, 'private.raw.hex'), 'w').write(priv_raw)
open(os.path.join(out_dir, 'public.raw.hex'), 'w').write(pub_raw)

print('WROTE', out_dir)
