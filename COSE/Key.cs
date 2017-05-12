using System;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Math.EC;

namespace Com.AugustCellars.COSE
{
    /// <summary>
    /// Class which holds information about a key
    /// </summary>
    public class OneKey : Key
    {
        /// <summary>
        /// Default constructor to create an empty key object
        /// </summary>
        public OneKey() { }

        /// <summary>
        /// Create a key object from a CBOR encoding
        /// </summary>
        /// <param name="objKey"></param>
        public OneKey(CBORObject objKey) : base(objKey) { }

        /// <summary>
        /// Return a new key object which the private key fields filtered out.
        /// </summary>
        /// <returns></returns>
        /// 
        public OneKey PublicKey()
        {
            OneKey newKey = new OneKey();
            switch ((GeneralValuesInt)m_map[CoseKeyKeys.KeyType].AsInt16())
            {
            case GeneralValuesInt.KeyType_Octet:
                return null;

            case GeneralValuesInt.KeyType_RSA:
                newKey.Add(CoseKeyParameterKeys.RSA_n, m_map[CoseKeyParameterKeys.RSA_n]);
                newKey.Add(CoseKeyParameterKeys.RSA_e, m_map[CoseKeyParameterKeys.RSA_e]);
                break;

            case GeneralValuesInt.KeyType_EC2:
                newKey.Add(CoseKeyParameterKeys.EC_Curve, m_map[CoseKeyParameterKeys.EC_Curve]);
                newKey.Add(CoseKeyParameterKeys.EC_X, m_map[CoseKeyParameterKeys.EC_X]);
                newKey.Add(CoseKeyParameterKeys.EC_Y, m_map[CoseKeyParameterKeys.EC_Y]);
                break;

            case GeneralValuesInt.KeyType_OKP:
                newKey.Add(CoseKeyParameterKeys.EC_Curve, m_map[CoseKeyParameterKeys.EC_Curve]);
                newKey.Add(CoseKeyParameterKeys.EC_X, m_map[CoseKeyParameterKeys.EC_X]);
                break;

            default:
                throw new CoseException("Key type unrecognized");
            }

            foreach (CBORObject obj in m_map.Keys) {
                switch (obj.Type) {
                    case CBORType.Number:
                        if (obj.AsInt32() > 0) {
                            newKey.Add(obj, m_map[obj]);
                        }
                        break;

                    case CBORType.TextString:
                        newKey.Add(obj, m_map[obj]);
                        break;

                }
            }
            return newKey;
        }

        public new X9ECParameters GetCurve()
        {
            return base.GetCurve();
        }

        public static OneKey GenerateKey(CBORObject algorithm = null, CBORObject keyType = null, string parameters = null)
        {
            if (keyType != null) {
                if (keyType.Equals(GeneralValues.KeyType_EC)) {
                    if (parameters == null) parameters = "P-256";
                    return generateEC2Key(algorithm, parameters);
                }
                else if (keyType.Equals(GeneralValues.KeyType_OKP)) {
                    if (parameters == null) parameters = "Ed25519";
                    return generateEDKey(algorithm, parameters);
                }
            }
            else {
                
            }
            return null;
        }

        private static OneKey generateEC2Key(CBORObject algorithm, string genParameters)
        {
            X9ECParameters p = NistNamedCurves.GetByName(genParameters);

            ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

            ECKeyPairGenerator pGen = new ECKeyPairGenerator();
            ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, new Org.BouncyCastle.Security.SecureRandom());
            pGen.Init(genParam);

            AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

            CBORObject epk = CBORObject.NewMap();
            epk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
            epk.Add(CoseKeyParameterKeys.EC_Curve, 1 /*  "P-256" */);
            ECPublicKeyParameters priv = (ECPublicKeyParameters)p1.Public;
            epk.Add(CoseKeyParameterKeys.EC_X, priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
            epk.Add(CoseKeyParameterKeys.EC_Y, priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());
            epk.Add(CoseKeyParameterKeys.EC_D, ((ECPrivateKeyParameters)p1.Private).D.ToByteArrayUnsigned());
            if (algorithm != null) epk.Add(CoseKeyKeys.Algorithm, algorithm);

            return new OneKey(epk);
        }

        private static OneKey generateEDKey(CBORObject algorithm, string genParameters)
        {
            X25519KeyPair pair = X25519KeyPair.GenerateKeyPair();

            CBORObject epk = CBORObject.NewMap();
            epk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
            if (genParameters == "Ed25519") epk.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.Ed25519);
            else if (genParameters == "X25519") epk.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.X25519);
            else throw new Exception("Bad parameter " + genParameters);
            epk.Add(CoseKeyParameterKeys.OKP_X, pair.Public);
            epk.Add(CoseKeyParameterKeys.OKP_D, pair.Private);
            if (algorithm != null) epk.Add(CoseKeyKeys.Algorithm, algorithm);

            return new OneKey(epk);
        }

        /// <summary>
        /// See if the key has an algorithm attribute that matches the parameter.
        /// If toMatch is null, it will match any algorithm, but requires one be present
        /// </summary>
        /// <param name="toMatch">Algorithm to match</param>
        /// <returns>boolean</returns>
        public Boolean HasAlgorithm(CBORObject toMatch)
        {
            CBORObject obj = m_map[CoseKeyKeys.Algorithm];
            if (toMatch == null) return obj != null;
            if (obj == null) return false;

            return obj.Equals(toMatch);
        }

        /// <summary>
        /// Does the key have the specified key type?
        /// </summary>
        /// <param name="keyType">Key type to be checked.</param>
        /// <returns></returns>
        public Boolean HasKeyType(int keyType)
        {
            CBORObject obj = m_map[CoseKeyKeys.KeyType];
            if (obj == null) return false;
            return obj.AsInt32() == keyType;
        }

        /// <summary>
        /// Check to see if the KID value matches
        /// </summary>
        /// <param name="kidToMatch">value of key to match</param>
        /// <returns>boolean</returns>
        public Boolean HasKid(byte[] kidToMatch)
        {
            CBORObject obj = m_map[CoseKeyKeys.KeyIdentifier];
            if (obj == null) return false;

            byte[] kid = obj.GetByteString();
            if (kid.Length != kidToMatch.Length) return false;

            Boolean ret = true;
            for (int i = 0; i < kid.Length; i++) if (kid[i] != kidToMatch[i]) ret = false;
            return ret;
        }

        /// <summary>
        /// Does the key contain a private key value.  This will only return true for 
        /// asymmetric keys.  A symmetric key will always return false.
        /// </summary>
        /// <returns>true if a private key exists.</returns>
        public Boolean HasPrivateKey()
        {
            try {
                switch ((GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt32()) {
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
    }

    /// <summary>
    /// Old version of the key structure, use OneKey instead.
    /// </summary>
    [Obsolete("The class OneKey should be used in place of Key.")]
    public class Key
    {
        protected CBORObject m_map;

        public Key()
        {
            m_map = CBORObject.NewMap();
        }

        public Key(CBORObject objKey)
        {
            m_map = objKey;
        }

        public void Add(CBORObject key, CBORObject value)
        {
            m_map.Add(key, value);
        }

        public void Add(string name, string value)
        {
            m_map.Add(name, value);
        }

        public void Add(string name, byte[] value)
        {
            m_map.Add(name, value);
        }

        private bool CompareField(Key key2, CBORObject key)
        {
            if (m_map.ContainsKey(key)) {
                if (!key2.m_map.ContainsKey(key)) return false;
                return m_map[key].CompareTo(key2.m_map[key]) == 0;
            }
            else {
                return !key2.m_map.ContainsKey(key);
            }
        }


        public bool Compare(Key key2)
        {
            if (!key2[CoseKeyKeys.KeyType].Equals(m_map[CoseKeyKeys.KeyType])) return false;
            if (!CompareField(key2, CoseKeyKeys.KeyIdentifier)) return false;
            if (!CompareField(key2, CoseKeyKeys.Algorithm)) return false;

            switch ((GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt32()) {
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
                    if (!CompareField(key2, CoseKeyParameterKeys.Octet_k)) return false;
                    break;

                default:
                    return true;
            }
            return true;
        }

        public Org.BouncyCastle.Math.BigInteger AsBigInteger(CBORObject keyName)
        {

            byte[] rgb = m_map[keyName].GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

        public CBORObject AsCBOR()
        {
            return m_map;
        }

        public CBORObject this[CBORObject name]
        {
            get { return m_map[name]; }
        }

        public byte[] AsBytes(CBORObject name)
        {
            return m_map[name].GetByteString();
        }

#if false
        public CBORObject AsObject(string name)
        {
            return m_map[name];
        }
#endif

        public string AsString(string name)
        {
            return m_map[name].AsString();
        }

        public Boolean ContainsName(string name)
        {
            return m_map.ContainsKey(name);
        }

        public Boolean ContainsName(CBORObject key)
        {
            return m_map.ContainsKey(key);
        }

        public byte[] EncodeToBytes()
        {
            return m_map.EncodeToBytes();
        }

        public CBORObject EncodeToCBORObject()
        {
            return m_map;
        }

        public GeneralValuesInt GetKeyType()
        {
            return (GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt32();
        }

        public X9ECParameters GetCurve()
        {
            CBORObject cborKeyType = m_map[CoseKeyKeys.KeyType];

            if (cborKeyType == null) throw new CoseException("Malformed key struture");
            if ((cborKeyType.Type != CBORType.Number) &&
                !((cborKeyType.Equals(GeneralValues.KeyType_EC)) || (cborKeyType.Equals(GeneralValues.KeyType_OKP)))) throw new CoseException("Not an EC key");

            CBORObject cborCurve = m_map[CoseKeyParameterKeys.EC_Curve];
            if (cborCurve.Type == CBORType.Number) {
                switch ((GeneralValuesInt) cborCurve.AsInt32()) {
                    case GeneralValuesInt.P256: return NistNamedCurves.GetByName("P-256");
                    case GeneralValuesInt.P384: return NistNamedCurves.GetByName("P-384");
                    case GeneralValuesInt.P521: return NistNamedCurves.GetByName("P-521");
                    case GeneralValuesInt.X25519: return CustomNamedCurves.GetByName("CURVE25519");
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
            else throw new CoseException("Incorrectly encoded key type");
        }

        public ECPoint GetPoint()
        {
            X9ECParameters p = GetCurve();
            ECPoint pubPoint;

            switch ((GeneralValuesInt) this[CoseKeyKeys.KeyType].AsInt32()) {
                case GeneralValuesInt.KeyType_EC2:
                    CBORObject y = m_map[CoseKeyParameterKeys.EC_Y];

                    if (y.Type == CBORType.Boolean) {
                        byte[] X = m_map[CoseKeyParameterKeys.EC_X].GetByteString();
                        byte[] rgb = new byte[X.Length + 1];
                        Array.Copy(X, 0, rgb, 1, X.Length);
                        rgb[0] = (byte) (2 + (y.AsBoolean() ? 1 : 0));
                        pubPoint = p.Curve.DecodePoint(rgb);
                    }
                    else {
                        pubPoint = p.Curve.CreatePoint(AsBigInteger(CoseKeyParameterKeys.EC_X), AsBigInteger(CoseKeyParameterKeys.EC_Y));
                    }
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    pubPoint = p.Curve.CreatePoint(AsBigInteger(CoseKeyParameterKeys.EC_X), new Org.BouncyCastle.Math.BigInteger("0"));
                    break;

                default:
                    throw new Exception("Unknown key type");
            }
            return pubPoint;
        }

        public Key PublicKey()
        {
            Key newKey = new Key();
            switch ((GeneralValuesInt) m_map[CoseKeyKeys.KeyType].AsInt16()) {
                case GeneralValuesInt.KeyType_Octet:
                    return null;

                case GeneralValuesInt.KeyType_RSA:
                    newKey.Add(CoseKeyParameterKeys.RSA_n, m_map[CoseKeyParameterKeys.RSA_n]);
                    newKey.Add(CoseKeyParameterKeys.RSA_e, m_map[CoseKeyParameterKeys.RSA_e]);
                    break;

                case GeneralValuesInt.KeyType_EC2:
                    newKey.Add(CoseKeyParameterKeys.EC_Curve, m_map[CoseKeyParameterKeys.EC_Curve]);
                    newKey.Add(CoseKeyParameterKeys.EC_X, m_map[CoseKeyParameterKeys.EC_X]);
                    newKey.Add(CoseKeyParameterKeys.EC_Y, m_map[CoseKeyParameterKeys.EC_Y]);
                    break;

                case GeneralValuesInt.KeyType_OKP:
                    newKey.Add(CoseKeyParameterKeys.OKP_Curve, m_map[CoseKeyParameterKeys.OKP_Curve]);
                    newKey.Add(CoseKeyParameterKeys.OKP_X, m_map[CoseKeyParameterKeys.OKP_X]);
                    break;

                default:
                    return null;
            }

            foreach (CBORObject obj in m_map.Keys) {
                switch (obj.Type) {
                    case CBORType.Number:
                        if (obj.AsInt32() > 0) {
                            newKey.Add(obj, m_map[obj]);
                        }
                        break;

                    case CBORType.TextString:
                        newKey.Add(obj, m_map[obj]);
                        break;

                }
            }
            return newKey;
        }

#if false
        public static Key NewKey()
        {
            if (false) {
                X9ECParameters p = NistNamedCurves.GetByName("P-256");

                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, new Org.BouncyCastle.Security.SecureRandom());
                pGen.Init(genParam);

                AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                CBORObject epk = CBORObject.NewMap();
                epk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
                epk.Add(CoseKeyParameterKeys.EC_Curve, 1 /*  "P-256" */);
                ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
                epk.Add(CoseKeyParameterKeys.EC_X, priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
                epk.Add(CoseKeyParameterKeys.EC_Y, priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());
                epk.Add(CoseKeyParameterKeys.EC_D, ((ECPrivateKeyParameters) p1.Private).D.ToByteArrayUnsigned());

                string xxx = epk.ToJSONString();

                return new COSE.Key(epk);
            }
            else {
                X9ECParameters p = CustomNamedCurves.GetByName("CURVE25519");

                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, new Org.BouncyCastle.Security.SecureRandom());
                pGen.Init(genParam);

                AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                CBORObject epk = CBORObject.NewMap();
                epk.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                epk.Add(CoseKeyParameterKeys.OKP_Curve, GeneralValues.X25519);
                ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
                epk.Add(CoseKeyParameterKeys.EC_X, priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
                epk.Add(CoseKeyParameterKeys.EC_D, ((ECPrivateKeyParameters) p1.Private).D.ToByteArrayUnsigned());

                string xxx = epk.ToJSONString();

                return new COSE.Key(epk);
            }
        }
#endif
    }
}
