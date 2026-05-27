using System;
using System.Text;
using Crossmool.Crypto;
using Crossmool.Crypto.Utils;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

class Program
{
    static void Main()
    {
        try
        {
            string signPubKeyHex = "3059301306072a8648ce3d020106082a811ccf5501822d034200048e9cad1b8638299dc3d61bb27c40db51ff63f59ac93ff9ef9cd0c53a3e060b3b379cfbcc68bdbe980129a684750aef5c767ed173d85bdf3e64828701e0ff54d4";
            
            // Java SM2Util signature on "hello"
            string javaSigHello = "3045022100b36a60c0f0a07959ce933734a24da31c4b0dc65bd671bf58c3d691bd7416164502201e77dc43a135df0d0c0ff5f815e75ae874aba7c3158776033b7e435b2ef9ca9a";
            
            // Java pure BC API signature on "hello" (from earlier run)
            string bcSigHello = "30440220360a0ffb05f07e5742c24e9176446cd14bba4e99cc88868056d9ec45f64b2c0d02206874b22b4edea6bcda1e72628f3e926df9bd6607013a4fdd08454badf0442c61";
            
            byte[] pubBytes = EncodingUtils.FromHex(signPubKeyHex);
            byte[] userId = Encoding.UTF8.GetBytes("1234567812345678");
            byte[] helloBytes = Encoding.UTF8.GetBytes("hello");
            
            // Parse public key via SubjectPublicKeyInfo
            var pubInfo = SubjectPublicKeyInfo.GetInstance(pubBytes);
            var pubKeyFromFactory = (ECPublicKeyParameters)PublicKeyFactory.CreateKey(pubInfo);
            
            Console.WriteLine("pubKey domain N: " + pubKeyFromFactory.Parameters.N.ToString(16).Substring(0, 20) + "...");
            Console.WriteLine("pubKey Q x: " + pubKeyFromFactory.Q.AffineXCoord.ToBigInteger().ToString(16).Substring(0, 20) + "...");
            
            // Verify Java SM2Util sig with factory-parsed key
            var v1 = new SM2Signer();
            v1.Init(false, new ParametersWithID(pubKeyFromFactory, userId));
            v1.BlockUpdate(helloBytes, 0, helloBytes.Length);
            bool r1 = v1.VerifySignature(EncodingUtils.FromHex(javaSigHello));
            Console.WriteLine("\nFactory key verify SM2Util sig: " + r1);
            
            // Verify Java BC sig with factory-parsed key
            var v2 = new SM2Signer();
            v2.Init(false, new ParametersWithID(pubKeyFromFactory, userId));
            v2.BlockUpdate(helloBytes, 0, helloBytes.Length);
            bool r2 = v2.VerifySignature(EncodingUtils.FromHex(bcSigHello));
            Console.WriteLine("Factory key verify BC sig: " + r2);
            
            // Now parse public key via SM2Util.ParsePublicKey (which calls ParsePublicKey internally)
            bool r3 = SM2Util.verify("hello", javaSigHello, signPubKeyHex);
            Console.WriteLine("\nSM2Util.verify SM2Util sig: " + r3);
            
            bool r4 = SM2Util.verify("hello", bcSigHello, signPubKeyHex);
            Console.WriteLine("SM2Util.verify BC sig: " + r4);
            
            // Now check: what domain does the factory-parsed key have?
            var factoryDomain = pubKeyFromFactory.Parameters;
            var sm2Curve = Org.BouncyCastle.Asn1.GM.GMNamedCurves.GetByName("sm2p256v1");
            var sm2Domain = new ECDomainParameters(sm2Curve.Curve, sm2Curve.G, sm2Curve.N, sm2Curve.H, sm2Curve.GetSeed());
            
            Console.WriteLine("\nFactory domain curve A: " + factoryDomain.Curve.A.ToBigInteger().ToString(16).Substring(0, 20) + "...");
            Console.WriteLine("Sm2Domain curve A: " + sm2Domain.Curve.A.ToBigInteger().ToString(16).Substring(0, 20) + "...");
            Console.WriteLine("Same A: " + factoryDomain.Curve.A.ToBigInteger().Equals(sm2Domain.Curve.A.ToBigInteger()));
            
            Console.WriteLine("\nFactory domain G x: " + factoryDomain.G.AffineXCoord.ToBigInteger().ToString(16).Substring(0, 20) + "...");
            Console.WriteLine("Sm2Domain G x: " + sm2Domain.G.AffineXCoord.ToBigInteger().ToString(16).Substring(0, 20) + "...");
            Console.WriteLine("Same G x: " + factoryDomain.G.AffineXCoord.ToBigInteger().Equals(sm2Domain.G.AffineXCoord.ToBigInteger()));
            
            // Re-create pubKey with Sm2Domain
            var pubKeyWithSm2Domain = new ECPublicKeyParameters(pubKeyFromFactory.Q, sm2Domain);
            
            var v5 = new SM2Signer();
            v5.Init(false, new ParametersWithID(pubKeyWithSm2Domain, userId));
            v5.BlockUpdate(helloBytes, 0, helloBytes.Length);
            bool r5 = v5.VerifySignature(EncodingUtils.FromHex(javaSigHello));
            Console.WriteLine("\nSm2Domain key verify SM2Util sig: " + r5);
            
            var v6 = new SM2Signer();
            v6.Init(false, new ParametersWithID(pubKeyWithSm2Domain, userId));
            v6.BlockUpdate(helloBytes, 0, helloBytes.Length);
            bool r6 = v6.VerifySignature(EncodingUtils.FromHex(bcSigHello));
            Console.WriteLine("Sm2Domain key verify BC sig: " + r6);
        }
        catch (Exception ex)
        {
            Console.WriteLine("Error: " + ex.Message + "\n" + ex.StackTrace);
        }
    }
}
