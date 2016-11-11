using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;


namespace JOSE
{
    public class SignMessage : Message
    {
        public byte[] payloadB64;
        public byte[] payload;

        List<Signer> signerList = new List<Signer>();
        
        public SignMessage()
        {

        }

        public SignMessage(JSON json)
        {
            //  Parse out the message from the JSON


            if (json.ContainsKey("signatures")) {
                JSON signers = json["signatures"];
                for (int i = 0; i < signers.Count; i++) {
                    Signer signer = new Signer(signers[i]);
                    signerList.Add(signer);
                }
            }
            else if (json.ContainsKey("signature")) {
                Signer signer = new Signer(json);
                signerList.Add(signer);
            }

            if (json.ContainsKey("payload")) {
                JSON b64 = signerList[0].FindAttribute("b64", true);
                if (b64 != null) {
                    if (b64.nodeType != JsonType.boolean) throw new Exception("Invalid message");
                    if (b64.AsBoolean()) {
                        payloadB64 = UTF8Encoding.UTF8.GetBytes(json["payload"].AsString());
                        payload = base64urldecode(json["payload"].AsString());
                    }
                    else {
                        payload = UTF8Encoding.UTF8.GetBytes(json["payload"].AsString());
                        payloadB64 = payload;
                    }
                }
                else {
                    payloadB64 = UTF8Encoding.UTF8.GetBytes(json["payload"].AsString());
                    payload = base64urldecode(json["payload"].AsString());
                }
            }

        }

        public void AddSigner(Signer sig)
        {
            signerList.Add(sig);
        }

        public string Encode()
        {
            JSON obj3;

            obj3 = EncodeToJSON();

            return obj3.ToString();
        }

        public string EncodeCompact()
        {
            JSON objBody;
            JSON objSigners = null;

            if (signerList.Count != 1) throw new JOSE_Exception("Compact mode not supported if more than one signer");
            if (objUnprotected.Count > 0) throw new JOSE_Exception("Compact mode not supported if unprotected attributes exist");

            ForceArray(true);
            objBody = EncodeToJSON();

            //  Base64 encoding says kill some messages
            

            if (objBody.ContainsKey("signatures")) objSigners = objBody["signatures"][0];

            string str = "";
            if (objSigners != null && objSigners.ContainsKey("protected")) str += objSigners["protected"].AsString();
            str += ".";
            if (objBody.ContainsKey("payload")) {
                if (objBody["payload"].AsString().Contains('.')) throw new Exception("Message cannot contain a period character");
                str += objBody["payload"].AsString();
            }
            str += ".";
            if (objSigners != null && objSigners.ContainsKey("signature")) str += objSigners["signature"].AsString();

            return str;
        }

        public JSON EncodeToJSON()
        {
            JSON obj = new JSON();
            
            if (objUnprotected.Count > 0) obj.Add("unprotected", objUnprotected); // Add unprotected attributes

            //  Look at the world of base64 encoded bodies.
            //   If any signer has the b64 false, then all of them need to.
            //   Then change our body if needed

            int b64Found = 0;
            bool b64Value = true;

            foreach( Signer key in signerList) {
                JSON attr = key.FindAttribute("b64", true);
                if (attr != null) {
                    if (b64Found == 0) b64Value = attr.AsBoolean();
                    else if (b64Value != attr.AsBoolean()) {
                        throw new JOSE_Exception("Not all signers using the same value for b64");
                    }
                    b64Found += 1;
                }
            }

            if (b64Value) {
                obj.Add("payload", base64urlencode(payload));
            }
            else {
                if (b64Found != signerList.Count) throw new JOSE_Exception("Not all signers using the same value for b64");
                obj.Add("payload", UTF8Encoding.UTF8.GetString(payload));
            }

            if ((signerList.Count == 1) && !forceAsArray) {
                JSON recipient = signerList[0].EncodeToJSON(payload);

                foreach (KeyValuePair<string, JSON> pair in recipient.map) {
                    obj.Add(pair.Key, pair.Value);
                }
            }
            else if (signerList.Count > 0) {
                JSON signers = new JSON();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToJSON(payload));
                }
                obj.Add("signatures", signers);
            }

            return obj;
        }

        public string GetContentAsString()
        {
            if (payload == null) throw new JOSE_Exception("No content to be found");
            return UTF8Encoding.UTF8.GetString(payload);
        }

        public void SetContent(string value)
        {
            payload = UTF8Encoding.UTF8.GetBytes(value);
            payloadB64 = UTF8Encoding.UTF8.GetBytes(base64urlencode(payload));
        }

        public void Verify(Key key)
        {
            foreach (Signer signer in signerList) {
                try {
                    signer.Verify(key, this);
                    return;
                }
                catch (JOSE_Exception e) { }
            }

            throw new JOSE_Exception("Validation of signature failed");
        }
    }

    public class Signer : Attributes
    {
        byte[] protectedB64;
        byte[] signature;
        static byte[] rgbDot = new byte[1] { 0x2e };
        Key keyToSign;

        public Signer(JSON jsonSigner)
        {
            if (jsonSigner.ContainsKey("protected")) {
                protectedB64 = UTF8Encoding.ASCII.GetBytes( jsonSigner["protected"].AsString());
                objProtected = JSON.Parse(UTF8Encoding.UTF8.GetString(Message.base64urldecode(jsonSigner["protected"].AsString())));
            }
            else {
                protectedB64 = new byte[0];
            }

            if (jsonSigner.ContainsKey("header")) {
                objUnprotected = jsonSigner["header"];
            }

            signature = Message.base64urldecode(jsonSigner["signature"].AsString());
        }

        public Signer(Key key, string algorithm = null)
        {
            if (algorithm != null) AddUnprotected("alg", algorithm);
            if (key.ContainsName("kid")) AddUnprotected("kid", key.AsString("kid"));

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "sig") throw new JOSE_Exception("Key cannot be used for encrytion");
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

        public JSON EncodeToJSON(byte[] body)
        {
            JSON obj = new JSON();
            string strProtected = "";

            if (objProtected.Count > 0) {
                strProtected = Message.base64urlencode(UTF8Encoding.UTF8.GetBytes(objProtected.ToString()));
                obj.Add("protected", strProtected);
            }

            if (objUnprotected.Count > 0) obj.Add("header", objUnprotected); // Add unprotected attributes

            String str = "";

            if (objProtected.ContainsKey("b64") && objProtected["b64"].AsBoolean() == false) {
                str += strProtected + "." + UTF8Encoding.UTF8.GetString(body);
            }
            else str += strProtected + "." + Message.base64urlencode( body );

            obj.Add("signature", Sign(UTF8Encoding.UTF8.GetBytes(str)));

            return obj;
        }

        private byte[] Sign(byte[] bytesToBeSigned)
        {
            string alg = null; // Get the set algorithm or infer one

            try {
                alg = FindAttribute("alg").AsString();
            }
            catch (Exception) {
                ;
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
                        throw new JOSE_Exception("Unknown curve");
                    }
                    break;

                default:
                    throw new JOSE_Exception("Unknown or unsupported key type " + keyToSign.AsString("kty"));
                }
                objUnprotected.Add("alg", alg);
            }

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
                throw new JOSE_Exception("Unknown signature algorithm");
            }


            switch (alg) {
            case "RS256":
            case "RS384":
            case "RS512": {
                RsaDigestSigner signer = new RsaDigestSigner(digest);
                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(ConvertBigNum(keyToSign.AsBytes("n")), ConvertBigNum(keyToSign.AsBytes("e")), ConvertBigNum(keyToSign.AsBytes("d")), ConvertBigNum(keyToSign.AsBytes("p")), ConvertBigNum(keyToSign.AsBytes("q")), ConvertBigNum(keyToSign.AsBytes("dp")), ConvertBigNum(keyToSign.AsBytes("dq")), ConvertBigNum(keyToSign.AsBytes("qi")));

                signer.Init(true, prv);
                signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                return signer.GenerateSignature();
                }

            case "PS256":
            case "PS384":
            case "PS512": {
                    PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetDigestSize());

                    RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(ConvertBigNum(keyToSign.AsBytes("n")), ConvertBigNum(keyToSign.AsBytes("e")), ConvertBigNum(keyToSign.AsBytes("d")), ConvertBigNum(keyToSign.AsBytes("p")), ConvertBigNum(keyToSign.AsBytes("q")), ConvertBigNum(keyToSign.AsBytes("dp")), ConvertBigNum(keyToSign.AsBytes("dq")), ConvertBigNum(keyToSign.AsBytes("qi")));
                    ParametersWithRandom rnd = new ParametersWithRandom(prv, Message.s_PRNG);

                    signer.Init(true, rnd);
                    signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                    return signer.GenerateSignature();
                }

            case "ES256":
            case "ES384":
            case "ES512": {
                    X9ECParameters p = NistNamedCurves.GetByName(keyToSign.AsString("crv"));
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(keyToSign.AsBytes("d")), parameters);
                    ParametersWithRandom param = new ParametersWithRandom(privKey, Message.s_PRNG);

                    ECDsaSigner ecdsa = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
                    ecdsa.Init(true, param);

                    BigInteger[] sig = ecdsa.GenerateSignature(bytesToBeSigned);
                    byte[] r = sig[0].ToByteArray();
                    byte[] s = sig[1].ToByteArray();
                    byte[] sigs = new byte[r.Length + s.Length];
                    Array.Copy(r, sigs, r.Length);
                    Array.Copy(s, 0, sigs, r.Length, s.Length);

                    return sigs;
                }

            case "HS256":
            case "HS384":
            case "HS512": {
                HMac hmac = new HMac(digest);

                KeyParameter key = new KeyParameter(keyToSign.AsBytes("k"));
                byte[] resBuf = new byte[hmac.GetMacSize()];

                hmac.Init(key);
                hmac.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                hmac.DoFinal(resBuf, 0);

                return resBuf;
                }

            case "EdDSA": {
                    switch (keyToSign.AsString("crv")) {
                    case "Ed25519":
                        COSE.EdDSA25517 x = new COSE.EdDSA25517();
                        return x.Sign(keyToSign.AsBytes("x"), keyToSign.AsBytes("d"), bytesToBeSigned);
                    }
                }
                break;

            }
            return null;
        }

        public void Verify(Key key, SignMessage msg)
        {
            string alg = FindAttr("alg", msg).AsString();
            COSE.EdDSA eddsa;

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
                throw new JOSE_Exception("Unknown signature algorithm");
            }



            switch (alg) {
            case "RS256":
            case "RS384":
            case "RS512": 
                {
                    if (key.AsString("kty") != "RSA") throw new JOSE_Exception("Wrong Key");
                    RsaDigestSigner signer = new RsaDigestSigner(digest);
                    RsaKeyParameters pub = new RsaKeyParameters(false, key.AsBigInteger("n"), key.AsBigInteger("e"));

                    signer.Init(false, pub);
                    signer.BlockUpdate(protectedB64, 0, protectedB64.Length);
                    signer.BlockUpdate(rgbDot, 0, 1);
                    signer.BlockUpdate(msg.payloadB64, 0, msg.payloadB64.Length);
                    if (!signer.VerifySignature(signature)) throw new JOSE_Exception("Message failed to verify");

                }
                break;

            case "PS256":
            case "PS384":
            case "PS512": 
                {
                    PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetDigestSize());
                    RsaKeyParameters pub = new RsaKeyParameters(false, key.AsBigInteger("n"), key.AsBigInteger("e"));

                    signer.Init(false, pub);
                    signer.BlockUpdate(protectedB64, 0, protectedB64.Length);
                    signer.BlockUpdate(rgbDot, 0, 1);
                    signer.BlockUpdate(msg.payloadB64, 0, msg.payloadB64.Length);
                    if (!signer.VerifySignature(signature)) throw new JOSE_Exception("Message failed to verify");
                }

                break;

            case "ES256":
            case "ES384":
            case "ES512":
                {
                    if (key.AsString("kty") != "EC") throw new JOSE_Exception("Wrong Key Type");
                    X9ECParameters p = NistNamedCurves.GetByName(key.AsString("crv"));
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPoint point = p.Curve.CreatePoint(key.AsBigInteger("x"
                        ), key.AsBigInteger("y")); 
                    ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, parameters);

                    ECDsaSigner ecdsa = new ECDsaSigner();
                    ecdsa.Init(false, pubKey);

                    digest.BlockUpdate(protectedB64, 0, protectedB64.Length);
                    digest.BlockUpdate(rgbDot, 0, rgbDot.Length);
                    digest.BlockUpdate(msg.payloadB64, 0, msg.payloadB64.Length);
                    byte[] o1 = new byte[digest.GetDigestSize()];
                    digest.DoFinal(o1, 0);
                    
                    BigInteger r = new BigInteger(signature, 0, signature.Length / 2);
                    BigInteger s = new BigInteger(signature, signature.Length / 2, signature.Length / 2);

                    if (!ecdsa.VerifySignature(o1, r, s)) throw new JOSE_Exception("Signature did not validate");
                }
                break;

            case "HS256":
            case "HS384":
            case "HS512": 
                {
                    HMac hmac = new HMac(digest);
                    KeyParameter K = new KeyParameter(Message.base64urldecode(key.AsString("k")));
                    hmac.Init(K);
                    hmac.BlockUpdate(protectedB64, 0, protectedB64.Length);
                    hmac.BlockUpdate(rgbDot, 0, rgbDot.Length);
                    hmac.BlockUpdate(msg.payloadB64, 0, msg.payloadB64.Length);

                    byte[] resBuf = new byte[hmac.GetMacSize()];
                    hmac.DoFinal(resBuf, 0);

                    bool fVerify = true;
                    for (int i = 0; i < resBuf.Length; i++) if (resBuf[i] != signature[i]) fVerify = false;

                    if (!fVerify) throw new JOSE_Exception("Signature did not validte");
                }
                break;

            case "EdDSA":
                if (key.AsString("kty") != "OKP") throw new JOSE_Exception("Wrong Key Type");
                switch (key.AsString("crv")) {
                case "Ed25519":
                    eddsa = new COSE.EdDSA25517();
                    break;

                default:
                    throw new JOSE_Exception("Unknown OKP curve");
                }
                COSE.EdDSAPoint eddsaPoint = eddsa.DecodePoint(key.AsBytes("x"));

                byte[] toVerify = new byte[protectedB64.Length + rgbDot.Length + msg.payloadB64.Length];
                Array.Copy(protectedB64, 0, toVerify, 0, protectedB64.Length);
                Array.Copy(rgbDot, 0, toVerify, protectedB64.Length, rgbDot.Length);
                Array.Copy(msg.payloadB64, 0, toVerify, protectedB64.Length + rgbDot.Length, msg.payloadB64.Length);

                if (!eddsa.Verify(key.AsBytes("x"), toVerify, signature)) throw new JOSE_Exception("Signature did not validate");

                break;
            
            default:
                throw new JOSE_Exception("Unknown algorithm");
            }
        }

        private Org.BouncyCastle.Math.BigInteger ConvertBigNum(byte[] rgb)
        {
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

    }
}
