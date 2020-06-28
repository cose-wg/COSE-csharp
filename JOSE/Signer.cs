using System;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public class Signer : Attributes
    {
        string protectedB64;
        byte[] signature;
        JWK keyToSign;

        public Signer(CBORObject jsonSigner)
        {
            if (jsonSigner.ContainsKey("protected")) {
                protectedB64 = jsonSigner["protected"].AsString();
                ProtectedMap = CBORObject.FromJSONString(Encoding.UTF8.GetString(Message.base64urldecode(jsonSigner["protected"].AsString())));
                if (ProtectedMap.Count == 0) {
                    throw new JoseException("field 'protected' must be omitted for empty maps.");
                }
            }

            if (jsonSigner.ContainsKey("header")) {
                UnprotectedMap = jsonSigner["header"];
            }
            else if (ProtectedMap.Count == 0) {
                throw new JoseException("One of 'protected' or 'header' must be present.");
            }

            if (!jsonSigner.ContainsKey("signature")) {
                throw new JoseException("Field 'signature' must be present.");
            }
            signature = Message.base64urldecode(jsonSigner["signature"].AsString());
        }

        public Signer(JWK key, string algorithm = null)
        {
            if (algorithm != null) AddAttribute("alg", algorithm, UNPROTECTED);
            if (key.ContainsName("kid")) AddAttribute("kid", key.AsString("kid"), UNPROTECTED);

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "sig") throw new JoseException("Key cannot be used for encrytion");
            }

#if false
            if (key.ContainsName("key_ops")) {
                JSON usageObject = key ["key_ops"];
                bool validUsage = false;

                if (usageObject.Type != CBORType.Array) throw new Exception("key_ops is incorrectly formed");
                for (int i = 0; i < usageObject.Count; i++) {
                    switch (usageObject[i].AsString()) {
                    case "encrypt":
                    case "keywrap":
                        validUsage = true;
                        break;
                    }
                }
                string usage = key.AsString("key_ops");
                if (!validUsage) throw new Exception("Key cannot be used for encryption");
            }
#endif

            keyToSign = key;
        }

        public void SetKey(JWK validateKey)
        {
            keyToSign = validateKey;
        }

        public CBORObject EncodeToJSON(byte[] body)
        {
            CBORObject obj = CBORObject.NewMap();

            if (protectedB64 != null) {
                obj.Add("protected", protectedB64);
            }
            else if (ProtectedMap.Count > 0) {
                protectedB64 = Message.base64urlencode(Encoding.UTF8.GetBytes(JSON.ToJsonString(ProtectedMap)));
                obj.Add("protected", protectedB64);
            }

            if (UnprotectedMap.Count > 0) obj.Add("header", UnprotectedMap); // Add unprotected attributes

            String str = "";

            if (ProtectedMap.ContainsKey("b64") && ProtectedMap["b64"].AsBoolean() == false) {
                str += protectedB64 + "." + Encoding.UTF8.GetString(body);
            }
            else {
                str += protectedB64 + "." + Message.base64urlencode(body);
            }

#if DEBUG
            ToBeSigned = str;
#endif

            obj.Add("signature", Message.base64urlencode(Sign(Encoding.UTF8.GetBytes(str))));

            return obj;
        }

#if DEBUG
        public string ToBeSigned { get; private set; }
#endif

        private byte[] Sign(byte[] bytesToBeSigned)
        {
            if (signature != null) {
                return signature;
            }


            string alg = null; // Get the set algorithm or infer one

            try {
                alg = FindAttribute("alg").AsString();
            }
            catch (Exception) {
                // ignored
            }

            if (alg == null) {
                switch (keyToSign.AsString("kty")) {
                case "RSA":
                    alg = "PS256";
                    break;

                case "EC":
                    switch (keyToSign.AsString("crv")) {
                    case "P-256":
                        alg = "ES256";
                        break;

                    case "P-384":
                        alg = "ES384";
                        break;

                    case "P-521":
                        alg = "ES512";
                        break;

                    default:
                        throw new JoseException("Unknown curve");
                    }

                    break;

                default:
                    throw new JoseException("Unknown or unsupported key type " + keyToSign.AsString("kty"));
                }

                UnprotectedMap.Add("alg", alg);
            }

            signature = keyToSign.ComputeMac(bytesToBeSigned, alg);
            return signature;
        }

        public bool Verify(SignMessage msg)
        {
            string alg = FindAttribute("alg").AsString();

            JWK key = keyToSign;

            IDigest digest;
            IDigest digest2;

            switch (alg) {
            case "RS256":
            case "ES256":
            case "PS256":
            case "HS256":
                digest = new Sha256Digest();
                digest2 = new Sha256Digest();
                break;

            case "RS384":
            case "ES384":
            case "PS384":
            case "HS384":
                digest = new Sha384Digest();
                digest2 = new Sha384Digest();
                break;

            case "RS512":
            case "ES512":
            case "PS512":
            case "HS512":
                digest = new Sha512Digest();
                digest2 = new Sha512Digest();
                break;

            case "EdDSA":
                digest = null;
                digest2 = null;
                break;

            default:
                throw new JoseException("Unknown signature algorithm");
            }

            //

            byte[] toBeSigned;
            string str = "";
            string body = Encoding.UTF8.GetString(msg.payloadB64);

            if (ProtectedMap.ContainsKey("b64") && ProtectedMap["b64"].AsBoolean() == false)
            {
                str += protectedB64 + "." + body;
            }
            else {
                str += protectedB64 + "." + body;
            }

            toBeSigned = Encoding.UTF8.GetBytes(str);


            switch (alg) {
            case "RS256":
            case "RS384":
            case "RS512": {
                if (key.AsString("kty") != "RSA") throw new JoseException("Wrong Key");
                RsaDigestSigner signer = new RsaDigestSigner(digest);
                RsaKeyParameters pub = new RsaKeyParameters(false, key.AsBigInteger("n"), key.AsBigInteger("e"));

                signer.Init(false, pub);
                signer.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                if (!signer.VerifySignature(signature)) throw new JoseException("Message failed to verify");

            }
                break;

            case "PS256":
            case "PS384":
            case "PS512": {
                PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest2.GetDigestSize());
                RsaKeyParameters pub = new RsaKeyParameters(false, key.AsBigInteger("n"), key.AsBigInteger("e"));

                signer.Init(false, pub);
                signer.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                if (!signer.VerifySignature(signature)) throw new JoseException("Message failed to verify");
            }

                break;

            case "ES256":
            case "ES384":
            case "ES512": {
                digest.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                byte[] o1 = new byte[digest.GetDigestSize()];
                digest.DoFinal(o1, 0);

                if (key.AsString("kty") != "EC") throw new JoseException("Wrong Key Type");

                ICipherParameters pubKey = keyToSign.AsPublicKey();
                ECDsaSigner ecdsa = new ECDsaSigner();
                ecdsa.Init(false, pubKey);

                BigInteger r = new BigInteger(1, signature, 0, signature.Length / 2);
                BigInteger s = new BigInteger(1, signature, signature.Length / 2, signature.Length / 2);

                if (!ecdsa.VerifySignature(o1, r, s)) throw new JoseException("Signature did not validate");
            }
                break;

            case "HS256":
            case "HS384":
            case "HS512": {
                HMac hmac = new HMac(digest);
                KeyParameter K = new KeyParameter(Message.base64urldecode(key.AsString("k")));
                hmac.Init(K);
                hmac.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
 
                byte[] resBuf = new byte[hmac.GetMacSize()];
                hmac.DoFinal(resBuf, 0);

                bool fVerify = true;
                for (int i = 0; i < resBuf.Length; i++) {
                    if (resBuf[i] != signature[i]) {
                        fVerify = false;
                    }
                }

                if (!fVerify) throw new JoseException("Signature did not validate");
            }
                break;

            case "EdDSA": {
                ISigner eddsa;
                if (key.AsString("kty") != "OKP") throw new JoseException("Wrong Key Type");
                switch (key.AsString("crv")) {
                case "Ed25519": {
                    Ed25519PublicKeyParameters privKey =
                        new Ed25519PublicKeyParameters(key.AsBytes("X"), 0);
                    eddsa = new Ed25519Signer();
                    eddsa.Init(false, privKey);

                    eddsa.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                    if (!eddsa.VerifySignature(signature)) throw new JoseException("Signature did not validate");

                    break;
                }

                default:
                    throw new JoseException("Unknown algorithm");
                }

                break;
            }

            default:
                throw new JoseException("Unknown algorithm");
            }

            return true;
        }

        private BigInteger ConvertBigNum(byte[] rgb)
        {
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) {
                rgb2[i + 2] = rgb[i];
            }

            return new BigInteger(rgb2);
        }

    }
}
