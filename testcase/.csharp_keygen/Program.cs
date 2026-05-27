using System;
using System.Text;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using System.Text.Json;

class Program
{
    static void Main()
    {
        var curve = GMNamedCurves.GetByName("sm2p256v1");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());
        var rng = new Org.BouncyCastle.Security.SecureRandom();
        
        var gen = new ECKeyPairGenerator();
        gen.Init(new ECKeyGenerationParameters(domain, rng));
        var pair = gen.GenerateKeyPair();
        
        var priv = (ECPrivateKeyParameters)pair.Private;
        var pub = (ECPublicKeyParameters)pair.Public;
        
        // X.509 public key
        var pubInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pub);
        var pubDer = pubInfo.GetEncoded();
        var pubHex = EncodingUtils.ToHex(pubDer);
        var pubB64 = EncodingUtils.ToBase64(pubDer);
        
        // PKCS#8 private key
        var privInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(priv);
        var privDer = privInfo.GetEncoded();
        var privHex = EncodingUtils.ToHex(privDer);
        var privB64 = EncodingUtils.ToBase64(privDer);
        
        var result = new {
            encryption_public_key = new { hex = pubHex, base64 = pubB64 },
            encryption_private_key = new { hex = privHex, base64 = privB64 },
            signature_private_key = new { hex = privHex, base64 = privB64 },
            signature_public_key = new { hex = pubHex, base64 = pubB64 }
        };
        
        Console.WriteLine(JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
    }
}
