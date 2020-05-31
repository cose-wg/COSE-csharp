using System;
using System.Collections.Generic;
using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace Com.AugustCellars.COSE
{
    /// <summary>
    /// Class which holds information about a key
    /// </summary>
    public class OneKey 
    {
        private readonly CBORObject _map;

        /// <summary>
        /// Default constructor to create an empty key object
        /// </summary>
        public OneKey()
        {
            _map = CBORObject.NewMap();

        }

        /// <summary>
        /// Create a key object from a CBOR encoding
        /// </summary>
        /// <param name="objKey"></param>
        public OneKey(CBORObject objKey)
        {
            _map = objKey;
        }

        public OneKey(AsymmetricKeyParameter publicKey, AsymmetricKeyParameter privateKey)
        {
            if (publicKey != null) {
                FromKey(publicKey);
                    
            }
            if (privateKey != null) {
                FromKey(privateKey);
            }
        }

        public static OneKey FromX509(byte[] x509)
        {
            X509Certificate cert = new X509CertificateParser().ReadCertificate(x509);

            SubjectPublicKeyInfo spki = cert.CertificateStructure.SubjectPublicKeyInfo;

            AsymmetricKeyParameter pub = PublicKeyFactory.CreateKey(spki);

            OneKey newKey = new OneKey();
            newKey.FromKey(pub);
            return newKey;
        }

        public static OneKey FromPkcs8(byte[] data)
        {
            AsymmetricKeyParameter akp = PrivateKeyFactory.CreateKey(data);

            OneKey key = new OneKey();
            key.FromKey(akp);

            return key;
        }

        public ICollection<CBORObject> Keys => _map.Keys;

        /// <summary>
        /// Add a field to the key structure
        /// </summary>
        /// <param name="label">label of field to be added</param>
        /// <param name="value">value to be added</param>
        public void Add(CBORObject label, CBORObject value)
        {
            _map.Add(label, value);
        }

        /// <summary>
        /// Add a field to the key structure
        /// </summary>
        /// <param name="name">label of the field to be added</param>
        /// <param name="value">value to be added</param>
        public void Add(string name, string value)
        {
            _map.Add(name, value);
        }

        /// <summary>
        /// Add a field tothe key structure
        /// </summary>
        /// <param name="name">label of the field to be added</param>
        /// <param name="value">value to be added</param>
        public void Add(string name, byte[] value)
        {
            _map.Add(name, value);
        }

        internal void Replace(CBORObject key, CBORObject value)
        {
            _map[key] = value;
        }

        /// <summary>
        /// See if a field in two keys is the same
        /// </summary>
        /// <param name="key2">2nd key to use</param>
        /// <param name="label">label of field to compare</param>
        /// <returns></returns>
        private bool CompareField(OneKey key2, CBORObject label)
        {
            if (_map.ContainsKey(label)) {
                if (!key2._map.ContainsKey(label)) {
                    return false;
                }

                return _map[label].Equals(key2._map[label]);
            }
            else {
                return !key2._map.ContainsKey(label);
            }
        }


        /// <summary>
        /// Compare to keys to see if they are equivalent.
        /// Comparison ignores a large number of fields.
        /// </summary>
        /// <param name="key2">Second key to compare</param>
        /// <returns></returns>
        public bool Compare(OneKey key2)
        {
            if (!key2[CoseKeyKeys.KeyType].Equals(_map[CoseKeyKeys.KeyType])) {
                return false;
            }

            if (!CompareField(key2, CoseKeyKeys.KeyIdentifier)) {
                return false;
            }

            if (!CompareField(key2, CoseKeyKeys.Algorithm)) {
                return false;
            }

            if (_map[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                switch (_map[CoseKeyKeys.KeyType].AsString()) {
                default:
                    return true;
                }
            }
            else {
                switch ((GeneralValuesInt) _map[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_RSA:
                    if (!CompareField(key2, CoseKeyParameterKeys.RSA_e) ||
                        !CompareField(key2, CoseKeyParameterKeys.RSA_n)) {
                        return false;
                    }

                    break;

                case GeneralValuesInt.KeyType_EC2:
                    if (!CompareField(key2, CoseKeyParameterKeys.EC_Curve) ||
                        !CompareField(key2, CoseKeyParameterKeys.EC_X) ||
                        !CompareField(key2, CoseKeyParameterKeys.EC_Y)) {
                        return false;
                    }

                    break;

                case GeneralValuesInt.KeyType_Octet:
                    if (!CompareField(key2, CoseKeyParameterKeys.Octet_k)) {
                        return false;
                    }

                    break;

                case GeneralValuesInt.KeyType_HssLms:
                    if (!CompareField(key2, CoseKeyParameterKeys.Lms_Public))
                    {
                        return false;
                    }
                    break;

                default:
                    return true;
                }
            }

            return true;
        }

        public BigInteger AsBigInteger(CBORObject keyName)
        {

            byte[] rgb = _map[keyName].GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) {
                rgb2[i + 2] = rgb[i];
            }

            return new BigInteger(rgb2);
        }

        public CBORObject AsCBOR()
        {
            return _map;
        }

        public CBORObject this[CBORObject name] {
            get =>_map[name];
        }

        public byte[] AsBytes(CBORObject name)
        {
            return _map[name].GetByteString();
        }

        public string AsString(string name)
        {
            return _map[name].AsString();
        }
        private AsymmetricKeyParameter PrivateKey { get; set; }

        public AsymmetricKeyParameter AsPrivateKey()
        {
            if (PrivateKey != null) {
                return PrivateKey;
            }

            switch (GetKeyType()) {
                case GeneralValuesInt.KeyType_EC2:
                    X9ECParameters p = GetCurve();
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(this[CoseKeyParameterKeys.EC_D]), parameters);
                    PrivateKey = privKey;
                    break;

                case GeneralValuesInt.KeyType_RSA:
                    RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(AsBigInteger(CoseKeyParameterKeys.RSA_n), AsBigInteger(CoseKeyParameterKeys.RSA_e), AsBigInteger(CoseKeyParameterKeys.RSA_d), AsBigInteger(CoseKeyParameterKeys.RSA_p), AsBigInteger(CoseKeyParameterKeys.RSA_q), AsBigInteger(CoseKeyParameterKeys.RSA_dP), AsBigInteger(CoseKeyParameterKeys.RSA_dQ), AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                    PrivateKey = prv;
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    switch ((GeneralValuesInt) this[CoseKeyParameterKeys.EC_Curve].AsInt32()) {
                        case GeneralValuesInt.Ed25519:
                            Ed25519PrivateKeyParameters privKeyEd25519 =
                                new Ed25519PrivateKeyParameters(this[CoseKeyParameterKeys.OKP_D].GetByteString(), 0);
                            PrivateKey = privKeyEd25519;
                            break;

                        case GeneralValuesInt.Ed448:
                            Ed448PrivateKeyParameters privKeyEd448 =
                                new Ed448PrivateKeyParameters(this[CoseKeyParameterKeys.OKP_D].GetByteString(), 0);
                            PrivateKey = privKeyEd448;
                            break;

                        default:
                            throw new CoseException("Unrecognaized curve for OKP key type");
                    }
                    break;

                default:
                    throw new CoseException("Unable to get the private key.");
            }
            return PrivateKey;
        }

        private AsymmetricKeyParameter _publicKey { get; set;  }

        public AsymmetricKeyParameter AsPublicKey()
        {
            switch (GetKeyType())
            {
                case GeneralValuesInt.KeyType_EC2:
                    X9ECParameters p = GetCurve();
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPoint point = GetPoint();
                    ECPublicKeyParameters param = new ECPublicKeyParameters(point, parameters);
                    _publicKey = param;
                    break;

                case GeneralValuesInt.KeyType_RSA:
                    RsaKeyParameters prv = new RsaKeyParameters(false, AsBigInteger(CoseKeyParameterKeys.RSA_n), AsBigInteger(CoseKeyParameterKeys.RSA_e));
                    _publicKey = prv;
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    switch ((GeneralValuesInt)this[CoseKeyParameterKeys.EC_Curve].AsInt32())
                    {
                        case GeneralValuesInt.Ed25519:
                            Ed25519PublicKeyParameters privKeyEd25519 =
                                new Ed25519PublicKeyParameters(this[CoseKeyParameterKeys.OKP_X].GetByteString(), 0);
                            _publicKey = privKeyEd25519;

                            break;

                        case GeneralValuesInt.Ed448:
                            Ed448PublicKeyParameters privKeyEd448 =
                                new Ed448PublicKeyParameters(this[CoseKeyParameterKeys.OKP_X].GetByteString(), 0);
                            _publicKey = privKeyEd448;

                            break;

                        default:
                            throw new CoseException("Unrecognaized curve for OKP key type");
                    }
                    break;

                default:
                    throw new CoseException("Unable to get the public key.");
            }

            return _publicKey;
        }

        public Boolean ContainsName(string name)
        {
            return _map.ContainsKey(name);
        }

        public Boolean ContainsName(CBORObject key)
        {
            return _map.ContainsKey(key);
        }

        public byte[] EncodeToBytes()
        {
            return _map.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            return _map;
        }

        public GeneralValuesInt GetKeyType()
        {
            return (GeneralValuesInt) _map[CoseKeyKeys.KeyType].AsInt32();
        }

        public X9ECParameters GetCurve()
        {
            CBORObject cborKeyType = _map[CoseKeyKeys.KeyType];

            if (cborKeyType == null) {
                throw new CoseException("Malformed key struture");
            }

            if ((cborKeyType.Type != CBORType.Integer) &&
                !((cborKeyType.Equals(GeneralValues.KeyType_EC)) || (cborKeyType.Equals(GeneralValues.KeyType_OKP)))) {
                throw new CoseException("Not an EC key");
            }

            CBORObject cborCurve = _map[CoseKeyParameterKeys.EC_Curve];
            if (cborCurve.Type == CBORType.Integer) {
                switch ((GeneralValuesInt) cborCurve.AsInt32()) {
                    case GeneralValuesInt.P256:
                        return NistNamedCurves.GetByName("P-256");
                    case GeneralValuesInt.P384:
                        return NistNamedCurves.GetByName("P-384");
                    case GeneralValuesInt.P521:
                        return NistNamedCurves.GetByName("P-521");
                    case GeneralValuesInt.X25519:
                        return CustomNamedCurves.GetByName("CURVE25519");
                    default:
                        throw new CoseException("Unsupported key type: " + cborKeyType.AsInt32());
                }
            }
            else if (cborCurve.Type == CBORType.TextString) {
                switch (cborCurve.AsString()) {
                    default:
                        throw new CoseException("Unsupported key type: " + cborKeyType.AsString());
                }
            }
            else {
                throw new CoseException("Incorrectly encoded key type");
            }
        }

        public ECPoint GetPoint()
        {
            X9ECParameters p = GetCurve();
            ECPoint pubPoint;

            switch ((GeneralValuesInt) this[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_EC2:
                    CBORObject y = _map[CoseKeyParameterKeys.EC_Y];

                    if (y.Type == CBORType.Boolean) {
                        byte[] x = _map[CoseKeyParameterKeys.EC_X].GetByteString();
                        byte[] rgb = new byte[x.Length + 1];
                        Array.Copy(x, 0, rgb, 1, x.Length);
                        rgb[0] = (byte) (2 + (y.AsBoolean() ? 1 : 0));
                        pubPoint = p.Curve.DecodePoint(rgb);
                    }
                    else {
                        pubPoint = p.Curve.CreatePoint(AsBigInteger(CoseKeyParameterKeys.EC_X), AsBigInteger(CoseKeyParameterKeys.EC_Y));
                    }
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    pubPoint = p.Curve.CreatePoint(AsBigInteger(CoseKeyParameterKeys.EC_X), new BigInteger("0"));
                    break;

                default:
                    throw new Exception("Unknown key type");
            }
            return pubPoint;
        }

        /// <summary>
        /// Return a new key object which the private key fields filtered out.
        /// </summary>
        /// <returns></returns>
        /// 
        public OneKey PublicKey()
        {
            OneKey newKey = new OneKey();
            if (_map[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                    throw new CoseException("Key type unrecognized");
            }
            else {
                switch ((GeneralValuesInt) _map[CoseKeyKeys.KeyType].AsInt16()) {
                case GeneralValuesInt.KeyType_Octet:
                    return null;

                case GeneralValuesInt.KeyType_RSA:
                    newKey.Add(CoseKeyParameterKeys.RSA_n, _map[CoseKeyParameterKeys.RSA_n]);
                    newKey.Add(CoseKeyParameterKeys.RSA_e, _map[CoseKeyParameterKeys.RSA_e]);
                    break;

                case GeneralValuesInt.KeyType_EC2:
                    newKey.Add(CoseKeyParameterKeys.EC_Curve, _map[CoseKeyParameterKeys.EC_Curve]);
                    newKey.Add(CoseKeyParameterKeys.EC_X, _map[CoseKeyParameterKeys.EC_X]);
                    newKey.Add(CoseKeyParameterKeys.EC_Y, _map[CoseKeyParameterKeys.EC_Y]);
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    newKey.Add(CoseKeyParameterKeys.EC_Curve, _map[CoseKeyParameterKeys.EC_Curve]);
                    newKey.Add(CoseKeyParameterKeys.EC_X, _map[CoseKeyParameterKeys.EC_X]);
                    break;

                case GeneralValuesInt.KeyType_HssLms:
                    newKey.Add(CoseKeyParameterKeys.Lms_Public, _map[CoseKeyParameterKeys.Lms_Public]);
                    break;

                default:
                    throw new CoseException("Key type unrecognized");
                }
            }

            foreach (CBORObject obj in _map.Keys) {
                switch (obj.Type) {
                    case CBORType.Integer:
                        if (obj.AsInt32() > 0) {
                            newKey.Add(obj, _map[obj]);
                        }
                        break;

                    case CBORType.TextString:
                        newKey.Add(obj, _map[obj]);
                        break;

                }
            }
            return newKey;
        }



        public static OneKey GenerateKey(CBORObject algorithm = null, CBORObject keyType = null, string parameters = null)
        {
            if (keyType != null) {
                if (keyType.Equals(GeneralValues.KeyType_EC)) {
                    if (parameters == null) parameters = "P-256";
                    return GenerateEC2Key(algorithm, parameters);
                }
                else if (keyType.Equals(GeneralValues.KeyType_OKP)) {
                    if (parameters == null) parameters = "Ed25519";
                    return GenerateEDKey(algorithm, parameters);
                }
                else if (keyType.Equals(GeneralValues.KeyType_RSA)) {
                    if (parameters == null) parameters = "RSA-256";
                    return GenerateRsaKey(algorithm, parameters);
                }
            }
            else {
                
            }
            return null;
        }

        private static OneKey GenerateEC2Key(CBORObject algorithm, string genParameters)
        {
            X9ECParameters p = NistNamedCurves.GetByName(genParameters);

            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            ECKeyPairGenerator pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, new SecureRandom());
            pGen.Init(genParam);

            AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

            OneKey newKey = new OneKey();
            newKey.FromKey(p1.Public);
            OneKey privKey = new OneKey();
            privKey.FromKey(p1.Private);
            foreach (CBORObject key in privKey.Keys) {
                if (newKey.ContainsName(key)) {
                    if (!privKey[key].Equals(newKey[key])) {
                        throw new CoseException("Internal error merging keys");
                    }
                }
                else {
                    newKey.Add(key, privKey[key]);
                }
            }
            if (algorithm != null) newKey._map.Add(CoseKeyKeys.Algorithm, algorithm);

            return newKey;
        }

        private Dictionary<string, CBORObject> algs = new Dictionary<string, CBORObject>() {
            {"1.2.840.10045.3.1.7", GeneralValues.P256 }
        };

        private void FromKey(AsymmetricKeyParameter x)
        {
            if (x is ECPrivateKeyParameters) {
                ECPrivateKeyParameters priv = (ECPrivateKeyParameters) x;
                Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
                Add(CoseKeyParameterKeys.EC_Curve, GeneralValues.P256); //  algs[priv.PublicKeyParamSet.Id]);
                Add(CoseKeyParameterKeys.EC_D, CBORObject.FromObject(priv.D.ToByteArrayUnsigned()));
                PrivateKey = x;
            }
            else if (x is ECPublicKeyParameters) {
                ECPublicKeyParameters pub = (ECPublicKeyParameters) x;
                _map.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
                _map.Add(CoseKeyParameterKeys.EC_Curve, GeneralValues.P256); // algs[pub.PublicKeyParamSet.Id]);
                _map.Add(CoseKeyParameterKeys.EC_X, pub.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
                _map.Add(CoseKeyParameterKeys.EC_Y, pub.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());
                _publicKey = x;
            }
            else if (x is Ed25519PrivateKeyParameters) {
                Ed25519PrivateKeyParameters priv = (Ed25519PrivateKeyParameters)x;
                _map.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                _map.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.Ed25519);
                _map.Add(CoseKeyParameterKeys.OKP_D, priv.GetEncoded());
            }
            else if (x is Ed25519PublicKeyParameters) {
                Ed25519PublicKeyParameters pub = (Ed25519PublicKeyParameters)x;
                _map.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                _map.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.Ed25519);
                _map.Add(CoseKeyParameterKeys.OKP_X, pub.GetEncoded());
            }
            else if (x is X25519PublicKeyParameters) {
                X25519PublicKeyParameters pub = (X25519PublicKeyParameters) x;
                _map.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                _map.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.X25519);
                _map.Add(CoseKeyParameterKeys.OKP_X, pub.GetEncoded());
            }
            else if (x is X25519PrivateKeyParameters) {
                X25519PrivateKeyParameters priv = (X25519PrivateKeyParameters)x;
                _map.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                _map.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.X25519);
                _map.Add(CoseKeyParameterKeys.OKP_D, priv.GetEncoded());
            }
            else {
                throw new CoseException("Unrecognized key type");
            }
        }

        private static OneKey GenerateEDKey(CBORObject algorithm, string genParameters)
        {
            OneKey newKey = new OneKey();
            OneKey privKey = new OneKey();
            switch (genParameters) {
            case "Ed25519": {
                Ed25519KeyPairGenerator pg = new Ed25519KeyPairGenerator();
                KeyGenerationParameters para = new Ed25519KeyGenerationParameters(new SecureRandom());
                        pg.Init(para);
                        AsymmetricCipherKeyPair cs = pg.GenerateKeyPair();
                privKey.FromKey(cs.Private);
                newKey.FromKey(cs.Public);
                break;
            }

            case "X25519": {
                X25519KeyPairGenerator pg = new X25519KeyPairGenerator();
                KeyGenerationParameters para = new X25519KeyGenerationParameters(new SecureRandom());
                pg.Init(para);
                AsymmetricCipherKeyPair cs = pg.GenerateKeyPair();
                privKey.FromKey(cs.Private);
                newKey.FromKey(cs.Public);

                break;
            }

            default:
                throw new Exception("Bad parameter " + genParameters);
            }

            foreach (CBORObject key in privKey.Keys) {
                if (newKey.ContainsName(key)) {
                    if (!privKey[key].Equals(newKey[key])) {
                        throw new CoseException("Internal error merging keys");
                    }
                }
                else {
                    newKey.Add(key, privKey[key]);
                }
            }

            if (algorithm != null) newKey._map.Add(CoseKeyKeys.Algorithm, algorithm);

            return newKey;
        }

        private static OneKey GenerateRsaKey(CBORObject algorithm, string parameters)
        {
            RsaKeyPairGenerator pGen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters genParam = new RsaKeyGenerationParameters(new BigInteger(1, new byte[] {0x1, 0x0, 0x1}), new SecureRandom(), Int32.Parse(parameters), 5);
            pGen.Init(genParam);

            AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

            CBORObject rsaKey = CBORObject.NewMap();
            rsaKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_RSA);
            RsaKeyParameters pub = (RsaKeyParameters)p1.Public;
            rsaKey.Add(CoseKeyParameterKeys.RSA_n, pub.Modulus.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_e, pub.Exponent.ToByteArrayUnsigned());

            RsaPrivateCrtKeyParameters priv = (RsaPrivateCrtKeyParameters) p1.Private;
            rsaKey.Add(CoseKeyParameterKeys.RSA_d, priv.Exponent.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_p, priv.P.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_q, priv.Q.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_dP, priv.DP.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_dQ, priv.DQ.ToByteArrayUnsigned());
            rsaKey.Add(CoseKeyParameterKeys.RSA_qInv, priv.QInv.ToByteArrayUnsigned());

            if (algorithm != null) rsaKey.Add(CoseKeyKeys.Algorithm, algorithm);

            return new OneKey(rsaKey);
        }


        /// <summary>
        /// See if the key has an algorithm attribute that matches the parameter.
        /// If toMatch is null, it will match any algorithm, but requires one be present
        /// </summary>
        /// <param name="toMatch">Algorithm to match</param>
        /// <returns>boolean</returns>
        public bool HasAlgorithm(CBORObject toMatch)
        {
            CBORObject obj = _map[CoseKeyKeys.Algorithm];
            if (toMatch == null) return obj != null;
            if (obj == null) return false;

            return obj.Equals(toMatch);
        }

        /// <summary>
        /// Does the key have the specified key type?
        /// </summary>
        /// <param name="keyType">Key type to be checked.</param>
        /// <returns></returns>
        public bool HasKeyType(int keyType)
        {
            CBORObject obj = _map[CoseKeyKeys.KeyType];
            if (obj == null) return false;
            return obj.AsInt32() == keyType;
        }

        /// <summary>
        /// Does the key have the specified key type?
        /// </summary>
        /// <param name="keyType">Key type to be checked.</param>
        /// <returns></returns>
        public bool HasKeyType(CBORObject keyType)
        {
            CBORObject obj = _map[CoseKeyKeys.KeyType];
            if (obj == null) return false;
            return obj.Equals(keyType);
        }

        /// <summary>
        /// Check to see if the KID value matches
        /// </summary>
        /// <param name="kidToMatch">value of key to match</param>
        /// <returns>boolean</returns>
        public Boolean HasKid(byte[] kidToMatch)
        {
            CBORObject obj = _map[CoseKeyKeys.KeyIdentifier];
            if (obj == null) return false;

            byte[] kid = obj.GetByteString();
            if (kid.Length != kidToMatch.Length) return false;

            bool ret = true;
            for (int i = 0; i < kid.Length; i++) {
                if (kid[i] != kidToMatch[i]) ret = false;
            }

            return ret;
        }

        /// <summary>
        /// Does the key contain a private key value.  This will only return true for 
        /// asymmetric keys.  A symmetric key will always return false.
        /// </summary>
        /// <returns>true if a private key exists.</returns>
        public bool HasPrivateKey()
        {
            try {
                switch ((GeneralValuesInt) _map[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_EC2:
                    return ContainsName(CoseKeyParameterKeys.EC_D);

                case GeneralValuesInt.KeyType_OKP:
                    return ContainsName(CoseKeyParameterKeys.OKP_D);
                }
            }
            catch (Exception) {
                // ignored
            }

            return false;
        }


        /// <summary>
        /// Location to store user defined data that is associated with a key.
        /// </summary>
        public object UserData { get; set; }

        private static BigInteger ConvertBigNum(CBORObject cbor)
        {
            byte[] rgb = cbor.GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) {
                rgb2[i + 2] = rgb[i];
            }

            return new BigInteger(rgb2);
        }

    }

    /// <summary>
    /// Old version of the key structure, use OneKey instead.
    /// </summary>
    [Obsolete("The class OneKey should be used in place of Key.")]
    public class Key : OneKey
    {
        public Key()
        {
        }

        public Key(CBORObject objKey) : base(objKey)
        {
        }
    }
}

