#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import json

data = {
    "encryption_public_key": {
        "hex": "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4",
        "base64": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEjpysG4Y4KZ3D1huyfEDbUf9j9ZrJP/nvnNDFOj4GCzs3n/vMaL2+mAEpaoRVCu9cdm7Rc9hb/z5kggfh4P9U1A=="
    },
    "encryption_private_key": {
        "hex": "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4",
        "base64": "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgcumU967gpP4dUH9ZGEzhoJLAVpFllEO6F7Dc0lqKsFeqCgYIKoEcz1UBgi2hRANCAAQ6mzYbhjgpnMPWG7J8QMtR/2P1msk/+e+c0MU6PgYLOzeP+8xovb6YASlqhHUK71x2ftFz2FvfPmSChwHg/1TQ",
        "format": "PKCS#8 HEX"
    },
    "signature_private_key": {
        "hex": "308193020100301306072a8648ce3d020106082a811ccf5501822d04793077020101042072e994f7aee0a4fe1d507f59184ce1a092c05691659443ba17b0dcd25a8ab057a00a06082a811ccf5501822da144034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4",
        "base64": "MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgcumU967gpP4dUH9ZGEzhoJLAVpFllEO6F7Dc0lqKsFeqCgYIKoEcz1UBgi2hRANCAAQ6mzYbhjgpnMPWG7J8QMtR/2P1msk/+e+c0MU6PgYLOzeP+8xovb6YASlqhHUK71x2ftFz2FvfPmSChwHg/1TQ",
        "format": "PKCS#8 HEX"
    },
    "signature_public_key": {
        "hex": "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4",
        "base64": "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEjpysG4Y4KZ3D1huyfEDbUf9j9ZrJP/nvnNDFOj4GCzs3n/vMaL2+mAEpaoRVCu9cdm7Rc9hb/z5kggfh4P9U1A==",
        "format": "X.509 HEX"
    }
}

with open("testcase/keys/javascript/keys.json", "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)

print("JavaScript keys.json 已生成")