using System;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public enum RecipientType
    {
        Direct = 1,
        KeyAgree = 2,
        KeyTransport = 3,
        KeyWrap = 4,
        KeyAgreeDirect = 5,
        KeyTransportAndWrap = 6,
        Password = 7
    }

    public class Recipient : Attributes
    {
        byte[] _rgbEncrypted;
        byte[] _payload;
        JWK _mKey;
        JWK _mSenderKey;

        public Recipient()
        {
        }

        public Recipient(JWK key, string algorithm = null, EncryptMessage msg = null)
        {
            if (algorithm == null && key.ContainsName("alg")) {
                algorithm = key.AsString("alg");
            }
            if (algorithm != null) {
                switch (algorithm) {
                case "dir": // Direct encryption mode
                    case "A128GCM":
                    case "A192GCM":
                    case "A256GCM":
                    if (key.AsString("kty") != "oct") throw new JoseException("Invalid parameters");
                    RecipientType = RecipientType.Direct;
                    algorithm = "dir";
                    break;

                case "ECDH-ES":
#if DEBUG
                case "ECDH-SS":
#endif // DEBUG
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JoseException("Invalid Parameters");
                    RecipientType = RecipientType.KeyAgreeDirect;
                    break;

                case "RSA1_5":
                case "RSA-OAEP":
                case "RSA-OAEP-256":
                    if (key.AsString("kty") != "RSA") throw new JoseException("Invalid Parameter");
                    RecipientType = RecipientType.KeyTransport;
                    break;

                case "A128KW":
                case "A192KW":
                case "A256KW":
                case "A128GCMKW":
                case "A192GCMKW":
                case "A256GCMKW":
                    if (key.AsString("kty") != "oct") throw new JoseException("Invalid Parameter");
                    RecipientType = RecipientType.KeyWrap;
                    break;

                case "ECDH-ES+A128KW":
                case "ECDH-ES+A192KW":
                case "ECDH-ES+A256KW":
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JoseException("Invalid Parameter");
                    RecipientType = RecipientType.KeyAgree;
                    break;

                case "PBES2-HS256+A128KW":
                case "PBES2-HS384+A192KW":
                case "PBES2-HS512+A256KW":
                    if (key.AsString("kty") != "oct") throw new JoseException("Invalid Parameter");
                    RecipientType = RecipientType.Password;
                    break;

                default:
                    throw new JoseException("Unrecognized recipient algorithm");
                }

                _mKey = key;
                if (FindAttr("alg", msg) == null) {
                    AddAttribute("alg", algorithm, UNPROTECTED);
                }
            }
            else {
                switch (key.AsString("kty")) {
                case "oct":
                    RecipientType = RecipientType.KeyWrap;
                    switch (key.AsBytes("k").Length) {
                    case 128 / 8:
                        algorithm = "A128KW";
                        break;

                    case 192 / 8:
                        algorithm = "A192KW";
                        break;

                    case 256 / 8:
                        algorithm = "A256KW";
                        break;

                    default:
                        throw new JoseException("Key size does not match any algorthms");
                    }

                    break;

                case "RSA":
                    RecipientType = RecipientType.KeyTransport;
                    algorithm = "RSA-OAEP-256";
                    break;

                case "EC":
                    RecipientType = RecipientType.KeyAgree;
                    algorithm = "ECDH-ES+A128KW";
                    break;
                }

                if (FindAttr("alg", msg) == null) {
                    AddAttribute("alg", algorithm, UNPROTECTED);
                }

                _mKey = key;
            }

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "enc") throw new JoseException("Key cannot be used for encrytion");
            }

            if (key.ContainsName("key_ops")) {
                string usageObject = key.AsString("key_ops");
                bool validUsage = false;

                string[] usageArray = usageObject.Split(',');
                for (int i = 0; i < usageArray.Length; i++) {
                    switch (usageArray[i]) {
                    case "encrypt":
                    case "keywrap":
                        validUsage = true;
                        break;
                    }
                }

                if (!validUsage) throw new JoseException("Key cannot be used for encryption");
            }

            if (key.ContainsName("kid") && (FindAttr("kid", msg) == null)) {
                AddAttribute("kid", key.AsString("kid"), UNPROTECTED);
            }
        }

        public RecipientType RecipientType { get; }

        public void DecodeFromJSON(CBORObject json)
        {
            if (json.Type != CBORType.Map) {
                throw new JoseException("recipient must be a map");
            }

            if (json.ContainsKey("header")) {
                UnprotectedMap = json["header"];
                if (UnprotectedMap.Type != CBORType.Map || UnprotectedMap.Count == 0) {
                    throw new JoseException("field 'header' must be a non-empty map");
                }
            }

            if (json.ContainsKey("encrypted_key")) {
                _rgbEncrypted = Message.base64urldecode(json["encrypted_key"].AsString());
            }
        }

        public byte[] Decrypt(int cbitKey, EncryptMessage msg)
        {

            JWK key = _mKey;
            if (key == null) {
                throw new JoseException("No key specified.");
            }
            string alg;

            alg = FindAttr("alg", msg).AsString();

            switch (alg) {
            case "dir":
                if (key.AsString("kty") != "oct") return null;
                return key.AsBytes("k");

            case "ECDH-ES": {
                if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) return null;

                byte[] secret = Ecdh(key, msg);
                byte[] kwKey = Kdf(secret, msg, cbitKey, FindAttr("enc", msg).AsString());
                return kwKey;
            }

            case "A128KW":
            case "A192KW":
            case "A256KW":
                if (key.AsString("kty") != "oct") return null;

                return AES_KeyWrap(key.AsBytes("k"));

            case "A128GCMKW":
            case "A192GCMKW":
            case "A256GCMKW":
                if (key.AsString("kty") != "oct") return null;
                return AESGCM_KeyWrap(key.AsBytes("k"), msg);

            case "PBES2-HS256+A128KW":
            case "PBES2-HS384+A192KW":
            case "PBES2-HS512+A256KW": {
                if (key.AsString("kty") != "oct") return null;
                byte[] saltInput = Message.base64urldecode(FindAttr("p2s", msg).AsString());
                byte[] algBytes = Encoding.UTF8.GetBytes(alg);
                byte[] salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);
                int iterCount = FindAttr("p2c", msg).AsInt32();

                byte[] rgbSecret = PBKDF2(key.AsBytes("k"), salt, iterCount, 256 / 8, new Sha512Digest());

                return AES_KeyWrap(rgbSecret);
            }

            case "RSA-OAEP-256":
            case "RSA-OAEP": {
                IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), alg == "RSA-OAEP" ? (IDigest) new Sha1Digest() : new Sha256Digest());
                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(key.AsBigInteger("n"), key.AsBigInteger("e"), key.AsBigInteger("d"), key.AsBigInteger("p"), key.AsBigInteger("q"),
                    key.AsBigInteger("dp"), key.AsBigInteger("dq"), key.AsBigInteger("qi"));

                cipher.Init(false, prv);
                byte[] outBytes = cipher.ProcessBlock(_rgbEncrypted, 0, _rgbEncrypted.Length);

                return outBytes;
            }

            case "ECDH-ES+A128KW": {
                if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) return null;

                byte[] secret = Ecdh(key, msg);
                byte[] kwKey = Kdf(secret, msg, 128, FindAttr("alg", msg).AsString());
                return AES_KeyWrap(kwKey);
            }

            case "ECDH-ES+A192KW": {
                if (key.AsString("kty") != "EC") return null;

                byte[] secret = Ecdh(key, msg);
                byte[] kwKey = Kdf(secret, msg, 192, FindAttr("alg", msg).AsString());
                return AES_KeyWrap(kwKey);
            }

            case "ECDH-ES+A256KW": {
                if (key.AsString("kty") != "EC") return null;

                byte[] secret = Ecdh(key, msg);
                byte[] kwKey = Kdf(secret, msg, 256, FindAttr("alg", msg).AsString());
                return AES_KeyWrap(kwKey);
            }

            case "RSA1_5": {
                if (key.AsString("kty") != "RSA") return null;

                IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());
                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(key.AsBigInteger("n"), key.AsBigInteger("e"), key.AsBigInteger("d"), key.AsBigInteger("p"), key.AsBigInteger("q"),
                    key.AsBigInteger("dp"), key.AsBigInteger("dq"), key.AsBigInteger("qi"));

                cipher.Init(false, prv);
                return cipher.ProcessBlock(_rgbEncrypted, 0, _rgbEncrypted.Length);
            }
            }

            return null;
        }

        public byte[] GetKey(string alg, EncryptMessage msg)
        {
            if (_mKey == null) return null;

            try {
                string keyAlgorithm = _mKey.AsString("alg");
                if (alg != keyAlgorithm) throw new JoseException("Algorithm mismatch between message and key");
            }
            catch (Exception) {
                // ignored
            }

            //  Figure out how longer the needed key is:

            int cbitKey;
            switch (alg) {
            case "A128GCM":
            case "AES-128-CCM-64":
                cbitKey = 128;
                break;

            case "A192GCM":
                cbitKey = 196;
                break;

            case "A256GCM":
            case "HS256":
                cbitKey = 256;
                break;

            case "HS384":
                cbitKey = 384;
                break;

            case "HS512":
                cbitKey = 512;
                break;

            case "A128CBC-HS256":
                cbitKey = 128 * 2;
                break;

            case "A192CBC-HS256":
                cbitKey = 192 * 2;
                break;

            case "A256CBC-HS256":
                cbitKey = 256 * 2;
                break;

            default:
                throw new JoseException("NYI");
            }

            string algKeyManagement = FindAttr("alg", msg).AsString();

            switch (algKeyManagement) {
            case "dir":
                if (_mKey.AsString("kty") != "oct") throw new JoseException("Key and key managment algorithm don't match");
                byte[] rgb = _mKey.AsBytes("k");
                if (rgb.Length * 8 != cbitKey) throw new JoseException("Incorrect key size");
                return rgb;

            case "ECDH-ES": {
                if ((_mKey.AsString("kty") != "EC") && (_mKey.AsString("kty") != "OKP")) throw new JoseException("Key and key management algorithm don't match");

                ECDH_GenerateEphemeral(msg);

                byte[] rgbSecret = ECDH_GenerateSecret(_mKey, msg);

                return Kdf(rgbSecret, msg, cbitKey, alg);
            }

            case "ECDH-SS": {
                if (_mKey.AsString("kty") != "EC") throw new JoseException("Key and key managment algorithm don't match");
                if (FindAttribute("apu") == null) {
                    byte[] rgbApu = new byte[512 / 8];
                    Message.s_PRNG.NextBytes(rgbApu);
                    AddAttribute("apu", CBORObject.FromObject(rgbApu), UNPROTECTED);
                }

                byte[] rgbSecret = ECDH_GenerateSecret(_mKey, msg);
                return Kdf(rgbSecret, msg, cbitKey, alg);
            }
            }

            throw new JoseException($"NYI: {alg}");
        }

        public void SetKey(JWK newKey)
        {
            _mKey = newKey;
        }

        public CBORObject EncodeToJSON()
        {
            CBORObject obj = CBORObject.NewMap();

            // if (rgbEncrypted == null) Encrypt();

            if (UnprotectedMap.Count > 0) obj.Add("header", UnprotectedMap); // Add unprotected attributes

            if (_rgbEncrypted != null) obj.Add("encrypted_key", Message.base64urlencode(_rgbEncrypted)); // Add ciphertext

            return obj;
        }

        public void Encrypt(EncryptMessage msg)
        {
            string alg; // Get the algorithm that was set.
            byte[] rgbSecret;
            byte[] rgbKey;
            CBORObject objSalt;
            CBORObject objIterCount;
            byte[] salt;
            byte[] saltInput;
            byte[] algBytes;

            alg = FindAttr("alg", msg).AsString();

            switch (alg) {
            case "dir":
            case "ECDH-ES":
            case "ECDH-SS":
                break;

            case "A128KW":
                AES_KeyWrap(128);
                break;
            case "A192KW":
                AES_KeyWrap(192);
                break;
            case "A256KW":
                AES_KeyWrap(256);
                break;

            case "RSA1_5":
                RSA_1_5_KeyWrap();
                break;

            case "RSA-OAEP":
                RSA_OAEP_KeyWrap(new Sha1Digest());
                break;
            case "RSA-OAEP-256":
                RSA_OAEP_KeyWrap(new Sha256Digest());
                break;

            case "ECDH-ES+A128KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(_mKey, msg);
                rgbKey = Kdf(rgbSecret, msg, 128, alg);
                AES_KeyWrap(128, rgbKey);
                break;

            case "ECDH-ES+A192KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(_mKey, msg);
                rgbKey = Kdf(rgbSecret, msg, 192, alg);
                AES_KeyWrap(192, rgbKey);
                break;

            case "ECDH-ES+A256KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(_mKey, msg);
                rgbKey = Kdf(rgbSecret, msg, 256, alg);
                AES_KeyWrap(256, rgbKey);
                break;

            case "A128GCMKW":
                AES_GCM_KeyWrap(128, msg);
                break;
            case "A192GCMKW":
                AES_GCM_KeyWrap(192, msg);
                break;
            case "A256GCMKW":
                AES_GCM_KeyWrap(256, msg);
                break;

            case "PBES2-HS256+A128KW":
                objSalt = FindAttribute("p2s");
                if (objSalt == null) {
                    salt = new byte[10];
                    Message.s_PRNG.NextBytes(salt);
                    objSalt = CBORObject.FromObject(salt);
                    AddAttribute("p2s", objSalt, UNPROTECTED);
                }

                objIterCount = FindAttribute("p2c");
                if (objIterCount == null) {
                    objIterCount = CBORObject.FromObject(8000);
                    AddAttribute("p2c", objIterCount, UNPROTECTED);
                }

                saltInput = Message.base64urldecode(objSalt.AsString());
                algBytes = Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKDF2(_mKey.AsBytes("k"), salt, objIterCount.AsInt32(), 128 / 8, new Sha256Digest());
                AES_KeyWrap(128, rgbKey);
                break;

            case "PBES2-HS384+A192KW":
                objSalt = FindAttribute("p2s");
                if (objSalt == null) {
                    salt = new byte[10];
                    Message.s_PRNG.NextBytes(salt);
                    objSalt = CBORObject.FromObject(salt);
                    AddAttribute("p2s", objSalt, UNPROTECTED);
                }

                objIterCount = FindAttribute("p2c");
                if (objIterCount == null) {
                    objIterCount = CBORObject.FromObject(8000);
                    AddAttribute("p2c", objIterCount, UNPROTECTED);
                }

                saltInput = Message.base64urldecode(FindAttr("p2s", msg).AsString());
                algBytes = Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKDF2(_mKey.AsBytes("k"), salt, objIterCount.AsInt32(), 192 / 8, new Sha384Digest());
                AES_KeyWrap(192, rgbKey);
                break;

            case "PBES2-HS512+A256KW":
                objSalt = FindAttr("p2s", msg);
                if (objSalt == null) {
                    salt = new byte[10];
                    Message.s_PRNG.NextBytes(salt);
                    objSalt = CBORObject.FromObject(salt);
                    AddAttribute("p2s", objSalt, UNPROTECTED);
                }

                objIterCount = FindAttr("p2c", msg);
                if (objIterCount == null) {
                    objIterCount = CBORObject.FromObject(8000);
                    AddAttribute("p2c", objIterCount, UNPROTECTED);
                }

                saltInput = Message.base64urldecode(objSalt.AsString());
                algBytes = Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKDF2(_mKey.AsBytes("k"), salt, objIterCount.AsInt32(), 256 / 8, new Sha512Digest());
                AES_KeyWrap(256, rgbKey);
                break;

            default:
                throw new JoseException("Unknown or unsupported algorithm: " + alg);
            }

        }

        public void SetContent(byte[] keyBytes)
        {
            _payload = keyBytes;
        }

        public void SetSenderKey(JWK senderKey)
        {
            _mSenderKey = senderKey;
        }


        private void RSA_1_5_KeyWrap()
        {
            IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, _mKey.AsBigInteger("n"), _mKey.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters, Message.s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(_payload, 0, _payload.Length);

            _rgbEncrypted = outBytes;
        }

        private void RSA_OAEP_KeyWrap(IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, _mKey.AsBigInteger("n"), _mKey.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters, Message.s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(_payload, 0, _payload.Length);

            _rgbEncrypted = outBytes;
        }

        private byte[] Ecdh(JWK key, EncryptMessage msg)
        {
            if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JoseException("Not an EC or OKP Key");

            CBORObject epkT = FindAttribute("epk");
            if (epkT == null) {
                epkT = msg.FindAttribute("epk");
                if (epkT == null) throw new JoseException("No Ephemeral key");
            }

            JWK epk = new JWK(epkT);

            if (epk.AsString("crv") != key.AsString("crv")) throw new JoseException("not a match of curves");

            //  Get the curve
            if (key.AsString("kty") == "EC") {
                X9ECParameters p = NistNamedCurves.GetByName(key.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                Org.BouncyCastle.Math.EC.ECPoint pubPoint = p.Curve.CreatePoint(epk.AsBigInteger("x"), epk.AsBigInteger("y"));
                ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                ECPrivateKeyParameters priv = new ECPrivateKeyParameters(key.AsBigInteger("d"), parameters);

                IBasicAgreement e1 = new ECDHBasicAgreement();
                e1.Init(priv);

                BigInteger k1 = e1.CalculateAgreement(pub);

                return k1.ToByteArrayUnsigned();
            }
            else {
                switch (epk.AsString("crv")) {
                case "X25519": {
                    X25519PublicKeyParameters pub =
                        new X25519PublicKeyParameters(epk.AsBytes("x"), 0);
                    X25519PrivateKeyParameters priv =
                        new X25519PrivateKeyParameters(key.AsBytes("d"), 0);

                    X25519Agreement agree = new X25519Agreement();
                    agree.Init(priv);
                    byte[] secret = new byte[32];
                    agree.CalculateAgreement(pub, secret, 0);
                    return secret;
                }

                default:
                    throw new JoseException("Unsupported curve");
                }
            }
        }

        private void ECDH_GenerateEphemeral(EncryptMessage msg)
        {
            CBORObject epk = CBORObject.NewMap();

            if (_mKey.AsString("kty") == "EC") {
                X9ECParameters p = NistNamedCurves.GetByName(_mKey.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, Message.s_PRNG);
                pGen.Init(genParam);

                AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                epk.Add("kty", "EC");
                epk.Add("crv", _mKey.AsString("crv"));
                ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
                epk.Add("x", priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
                epk.Add("y", priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());

            }
            else if (_mKey.AsString("kty") == "OKP") {
                switch (_mKey.AsString("crv")) {
                case "X25519":
                    Ed25519KeyPairGenerator pGen = new Ed25519KeyPairGenerator();
                    Ed25519KeyGenerationParameters genParam = new Ed25519KeyGenerationParameters(Message.s_PRNG);
                    pGen.Init(genParam);

                    AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();
                    Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters) p1.Public;

                    epk.Add("kty", "OKP");
                    epk.Add("crv", "X25519");
                    epk.Add("x", pub.GetEncoded());
                    break;

                default:
                    throw new JoseException("Unknown OPK curve");
                }
            }
            else {
                throw new JoseException("Internal Error");
            }

            if (msg.FindAttribute(CBORObject.FromObject("epk"), PROTECTED) != null) {
                msg.AddAttribute(CBORObject.FromObject("epk"), epk, PROTECTED);
            }
            else if (msg.FindAttribute(CBORObject.FromObject("epk"), PROTECTED) != null) {
                msg.AddAttribute(CBORObject.FromObject("epk"), epk, PROTECTED);
            }
            else {
                AddAttribute("epk", epk, UNPROTECTED);
            }
        }


        private byte[] ECDH_GenerateSecret(JWK key, EncryptMessage msg)
        {
            JWK epk;

            if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JoseException("Not an EC or OKP Key");

            if (_mSenderKey != null) {
                epk = _mSenderKey;
            }
            else {
                CBORObject epkT = FindAttr("epk", msg);
                if (epkT == null) throw new JoseException("No Ephemeral key");
                epk = new JWK(epkT);
            }

            if (epk.AsString("crv") != key.AsString("crv")) throw new JoseException("not a match of curves");

            if (key.AsString("kty") == "EC") {
                //  Get the curve

                X9ECParameters p = NistNamedCurves.GetByName(key.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                Org.BouncyCastle.Math.EC.ECPoint pubPoint = p.Curve.CreatePoint(epk.AsBigInteger("x"), epk.AsBigInteger("y"));
                ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                ECPrivateKeyParameters priv = new ECPrivateKeyParameters(key.AsBigInteger("d"), parameters);

                IBasicAgreement e1 = new ECDHBasicAgreement();
                e1.Init(priv);

                BigInteger k1 = e1.CalculateAgreement(pub);

                return k1.ToByteArrayUnsigned();
            }
            else {
                switch (epk.AsString("crv")) {
                case "X25519": {
                    X25519PublicKeyParameters pub =
                        new X25519PublicKeyParameters(epk.AsBytes("x"), 0);
                    X25519PrivateKeyParameters priv =
                        new X25519PrivateKeyParameters(key.AsBytes("d"), 0);

                    X25519Agreement agree = new X25519Agreement();
                    agree.Init(priv);
                    byte[] secret = new byte[32];
                    agree.CalculateAgreement(pub, secret, 0);
                    return secret;
                }

                default:
                    throw new JoseException("Unsupported curve");
                }
            }
        }

#if false
        private byte[] KDF(byte[] secret, int cbitKey, string algorithmID)
        {
            //  Build a long byte array
            //  four byte counter
            //  secret
            //  AlgorithmID - [32-bit size || algorithm identifier ]
            //  PartyUInfo - [32-bit size || PartyUInfo ] ---- "apu"
            //  PartyVInfo - [32-bit size || PartyVInfo ] ---- "apv"
            //  SuppPubInfo - 32-bit - key data len
            //  SuppPrivInfo - nothing

            byte[] rgbPartyU = new byte[0];
            byte[] rgbPartyV = new byte[0];
            byte[] algId = UTF8Encoding.UTF8.GetBytes(algorithmID);

            JSON j = FindAttribute("apu");
            if (j != null) rgbPartyU = j.AsBytes();

            j = FindAttribute("apv");
            if (j != null) rgbPartyV = j.AsBytes();

            int c = 4 + secret.Length + 4 + algId.Length + 4 + rgbPartyU.Length + 4 + rgbPartyV.Length + 4;
            byte[] rgb = new byte[c];

            //  Counter starts at 0

            Array.Copy(secret, 0, rgb, 4, secret.Length);
            c = 4 + secret.Length;

            if (algorithmID.Length > 255) throw new Exception("Internal error");
            rgb[c + 3] = (byte) algId.Length;
            Array.Copy(algId, 0, rgb, c + 4, algId.Length);
            c += 4 + algorithmID.Length;

            if (rgbPartyU.Length > 255) throw new Exception("Internal error");
            rgb[c + 3] = (byte) rgbPartyU.Length;
            Array.Copy(rgbPartyU, 0, rgb, c + 4, rgbPartyU.Length);
            c += 4 + rgbPartyU.Length;

            if (rgbPartyV.Length > 255) throw new Exception("internal error");
            rgb[c + 3] = (byte) rgbPartyV.Length;
            Array.Copy(rgbPartyV, 0, rgb, c + 4, rgbPartyV.Length);
            c += 4 + rgbPartyV.Length;

            if (cbitKey / (256 * 256) != 0) throw new Exception("internal error");
            rgb[c + 3] = (byte) (cbitKey % 256);
            rgb[c + 2] = (byte) (cbitKey / 256);

            //  Now do iterative hashing

            IDigest digest = new Sha256Digest();
            int cIters = (cbitKey + 255) / 256;
            byte[] rgbDigest = new byte[256 / 8 * cIters];

            for (int i = 0; i < cIters; i++) {
                rgb[3] = (byte) (i + 1);
                digest.Reset();
                digest.BlockUpdate(rgb, 0, rgb.Length);
                digest.DoFinal(rgbDigest, (256 / 8) * i);
            }

            byte[] rgbOut = new byte[cbitKey / 8];
            Array.Copy(rgbDigest, rgbOut, rgbOut.Length);
            return rgbOut;
            /*
             *                     //  Do the KDF function

                    CBORObject dataArray = CBORObject.NewArray();
                    dataArray.Add(0);
                    dataArray.Add(k1.ToByteArray());

                    string PartyUInfo = null;
                    if (objUnprotected.ContainsKey("PartyUInfo")) PartyUInfo = objUnprotected["PartyUInfo"].AsString();
                    dataArray.Add(PartyUInfo);

                    string PartyVInfo = null;
                    if (objUnprotected.ContainsKey("PartyVInfo")) PartyUInfo = objUnprotected["PartyVInfo"].AsString();
                    dataArray.Add(PartyVInfo);

                    byte[] SubPubInfo = new byte[4];
                    SubPubInfo[3] = (byte) cbitKey;
                    dataArray.Add(SubPubInfo);

                    dataArray.Add(null); // SubPrivInfo

                    byte[] rgbData = dataArray.EncodeToBytes();
                    Sha256Digest sha256 = new Sha256Digest();
                    sha256.BlockUpdate(rgbData, 0, rgbData.Length);
                    byte[] rgbOut = new byte[sha256.GetByteLength()];
                    sha256.DoFinal(rgbOut, 0);

                    byte[] rgbResult = new byte[cbitKey / 8];
                    Array.Copy(rgbOut, rgbResult, rgbResult.Length);
*/
        }
#endif

        private byte[] Kdf(byte[] secret, EncryptMessage msg, int cbitKey, string algorithmId)
        {
            //  Build a long byte array
            //  four byte counter
            //  secret
            //  AlgorithmID - [32-bit size || algorithm identifier ]
            //  PartyUInfo - [32-bit size || PartyUInfo ] ---- "apu"
            //  PartyVInfo - [32-bit size || PartyVInfo ] ---- "apv"
            //  SuppPubInfo - 32-bit - key data len
            //  SuppPrivInfo - nothing

            byte[] rgbPartyU = new byte[0];
            byte[] rgbPartyV = new byte[0];
            byte[] algId = Encoding.UTF8.GetBytes(algorithmId);

            CBORObject j = FindAttr("apu", msg);
            if (j != null) rgbPartyU = Message.base64urldecode(j.AsString());

            j = FindAttr("apv", msg);
            if (j != null) rgbPartyV = Message.base64urldecode(j.AsString());

            int c = 4 + secret.Length + 4 + algId.Length + 4 + rgbPartyU.Length + 4 + rgbPartyV.Length + 4;
            byte[] rgb = new byte[c];

            //  Counter starts at 0

            Array.Copy(secret, 0, rgb, 4, secret.Length);
            c = 4 + secret.Length;

            if (algorithmId.Length > 255) throw new JoseException("Internal error");
            rgb[c + 3] = (byte) algId.Length;
            Array.Copy(algId, 0, rgb, c + 4, algId.Length);
            c += 4 + algorithmId.Length;

            if (rgbPartyU.Length > 255) throw new JoseException("Internal error");
            rgb[c + 3] = (byte) rgbPartyU.Length;
            Array.Copy(rgbPartyU, 0, rgb, c + 4, rgbPartyU.Length);
            c += 4 + rgbPartyU.Length;

            if (rgbPartyV.Length > 255) throw new JoseException("internal error");
            rgb[c + 3] = (byte) rgbPartyV.Length;
            Array.Copy(rgbPartyV, 0, rgb, c + 4, rgbPartyV.Length);
            c += 4 + rgbPartyV.Length;

            if (cbitKey / (256 * 256) != 0) throw new JoseException("internal error");
            rgb[c + 3] = (byte) (cbitKey % 256);
            rgb[c + 2] = (byte) (cbitKey / 256);

            //  Now do iterative hashing

            IDigest digest = new Sha256Digest();
            int cIters = (cbitKey + 255) / 256;
            byte[] rgbDigest = new byte[256 / 8 * cIters];

            for (int i = 0; i < cIters; i++) {
                rgb[3] = (byte) (i + 1);
                digest.Reset();
                digest.BlockUpdate(rgb, 0, rgb.Length);
                digest.DoFinal(rgbDigest, (256 / 8) * i);
            }

            byte[] rgbOut = new byte[cbitKey / 8];
            Array.Copy(rgbDigest, rgbOut, rgbOut.Length);
            return rgbOut;
        }

        private byte[] AES_KeyWrap(byte[] key)
        {
            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(key);
            foo.Init(false, parameters);
            _payload = foo.Unwrap(_rgbEncrypted, 0, _rgbEncrypted.Length);
            return _payload;
        }

        private void AES_KeyWrap(int keySize, byte[] rgbKey = null)
        {
            if (rgbKey == null) {
                if (_mKey.AsString("kty") != "oct") throw new JoseException("Key is not correct type");

                rgbKey = _mKey.AsBytes("k");
            }

            if (rgbKey.Length != keySize / 8) throw new JoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(true, parameters);
            _rgbEncrypted = foo.Wrap(_payload, 0, _payload.Length);
        }

#if false
        private byte[] AES_KeyUnwrap(JWK keyObject, int keySize, byte[] rgbKey = null)
        {
            if (keyObject != null) {
                if (keyObject.AsString("kty") != "oct") return null;
                rgbKey = keyObject.AsBytes("k");
            }

            if (rgbKey != null && rgbKey.Length != keySize / 8) throw new JoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(false, parameters);
            _payload = foo.Unwrap(_rgbEncrypted, 0, _rgbEncrypted.Length);
            return _payload;
        }
#endif

        private void AES_GCM_KeyWrap(int keySize, EncryptMessage msg)
        {
            if (_mKey.AsString("kty") != "oct") throw new JoseException("Incorrect key type");
            byte[] keyBytes = _mKey.AsBytes("k");
            if (keyBytes.Length != keySize / 8) throw new JoseException("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter contentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            contentKey = new KeyParameter(keyBytes);
            byte[] a = new byte[0];
            byte[] iv = new byte[96 / 8];


            Message.s_PRNG.NextBytes(iv);
            if (msg.FindAttribute(CBORObject.FromObject("iv"), PROTECTED) != null) {
                msg.AddAttribute("iv", Message.base64urlencode(iv), PROTECTED);
            }
            else if (msg.FindAttribute(CBORObject.FromObject("iv"), UNPROTECTED) != null) {
                msg.AddAttribute("iv", Message.base64urlencode(iv), UNPROTECTED);
            }
            else {
                UnprotectedMap.Add("iv", Message.base64urlencode(iv));
            }

            AeadParameters parameters = new AeadParameters(contentKey, 128, iv, a);

            cipher.Init(true, parameters);
            byte[] c = new byte[cipher.GetOutputSize(_payload.Length)];
            int len = cipher.ProcessBytes(_payload, 0, _payload.Length, c, 0);
            len += cipher.DoFinal(c, len);

            if (len != c.Length) throw new JoseException("NYI");
            byte[] tag = new byte[128 / 8];
            Array.Copy(c, c.Length - tag.Length, tag, 0, tag.Length);

            if (msg.FindAttribute(CBORObject.FromObject("tag"), PROTECTED) != null) {
                msg.AddAttribute("tag", Message.base64urlencode(tag), PROTECTED);
            }
            else if (msg.FindAttribute(CBORObject.FromObject("tag"), UNPROTECTED) != null) {
                msg.AddAttribute("tag", Message.base64urlencode(tag), UNPROTECTED);
            }
            else {
                UnprotectedMap.Add("tag", Message.base64urlencode(tag));
            }

            _rgbEncrypted = c;
            Array.Resize(ref _rgbEncrypted, c.Length - tag.Length);
        }

        private byte[] AESGCM_KeyWrap(byte[] key, EncryptMessage msg)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter contentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            contentKey = new KeyParameter(key);
            byte[] a = new byte[0];
            byte[] iv = Message.base64urldecode(FindAttr("iv", msg).AsString());
            byte[] tag = Message.base64urldecode(FindAttr("tag", msg).AsString());

            AeadParameters parameters = new AeadParameters(contentKey, 128, iv, a);

            cipher.Init(false, parameters);
            byte[] c = new byte[cipher.GetOutputSize(_rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(_rgbEncrypted, 0, _rgbEncrypted.Length, c, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, c, len);
            cipher.DoFinal(c, len);

            return c;
        }

        public static byte[] PBKDF2(byte[] password, byte[] salt, int iterCount, int cOctets, IDigest digest)
        {
            //  PRF = HMAC- SHA (256, 384, 512)
            //  P = passsword
            //  S = salt
            //  c = iteration count
            //  dkLen = cbits in octets

            //  l = CIEL(dkLen / hLen)
            //  r = dkLen - (l - 1)*hLen

            // T_n = F ( P, S, c, n)  (iterate n=1 to l)

            // F ( P, S, c, i) = U_1 ^ U_2 ^ ... ^ U_c

            // U_1 = PRF( P, S || INT (i))
            // U_2 = PRF( P, U_1 )
            // U_c = PRF( P, U_{c-1})
            //  INT = int32- big-ending

            HMac hmac = new HMac(digest);
            ICipherParameters k = new KeyParameter(password);
            hmac.Init(k);
            int hLen = hmac.GetMacSize();
            int l = (cOctets + hLen - 1) / hLen;

            byte[] rgbStart = new byte[salt.Length + 4];
            Array.Copy(salt, 0, rgbStart, 0, salt.Length);
            byte[] rgbOutput = new byte[l * hLen];

            for (int i = 1; i <= l; i++) {
                byte[] rgbT = new byte[hLen];
                byte[] rgbH = new byte[hLen];

                hmac.Reset();
                rgbStart[rgbStart.Length - 1] = (byte) i;
                hmac.BlockUpdate(rgbStart, 0, rgbStart.Length);
                hmac.DoFinal(rgbH, 0);
                Array.Copy(rgbH, rgbT, rgbH.Length);

                for (int j = 1; j < iterCount; j++) {
                    hmac.Reset();
                    hmac.BlockUpdate(rgbH, 0, rgbH.Length);
                    hmac.DoFinal(rgbH, 0);
                    for (int k1 = 0; k1 < rgbH.Length; k1++) {
                        rgbT[k1] ^= rgbH[k1];
                    }
                }

                Array.Copy(rgbT, hLen * (i - 1), rgbOutput, 0, rgbT.Length);
            }

            byte[] rgbOut = new Byte[cOctets];
            Array.Copy(rgbOutput, rgbOut, cOctets);
            return rgbOut;
        }
    }
}
