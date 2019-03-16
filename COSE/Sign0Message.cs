using System;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Com.AugustCellars.COSE
{
    public class Sign1Message : Message
    {
        public Sign1Message(bool fEmitTag = true, bool fEmitContent = true) : base(fEmitTag, fEmitContent)
        {
            m_tag = Tags.Sign1;
        }

        public byte[] BEncodeToBytes()
        {
            CBORObject obj2 = BEncodeToCBORObject();

            return obj2.EncodeToBytes();
        }

        public CBORObject BEncodeToCBORObject()
        {
            CBORObject objX = EncodeToCBORObject();
            CBORObject obj = CBORObject.NewMap();

            if (objX[2] != null) obj[CBORObject.FromObject(1)] = objX[2];
            if (objX[3] != null) {
                CBORObject obj3 = CBORObject.NewArray();
                obj[CBORObject.FromObject(2)] = obj3;
                for (int i = 0; i < objX[3].Count; i++) {
                    CBORObject obj2 = CBORObject.NewMap();
                    obj3.Add(obj2);
                    obj2[CBORObject.FromObject(3)] = objX[3][i][2];
                    obj2[CBORObject.FromObject(4)] = objX[3][i][1];
                    if (objX[3][i][0] != null) {
                        obj2[CBORObject.FromObject(5)] = objX[3][i][0];
                    }
                }
            }
            return obj;
        }


 #region Decoders
        public static Sign1Message DecodeFromCBOR(CBORObject obj)
        {
            return (Sign1Message)Message.DecodeFromCBOR(obj, Tags.Sign1);
        }

        protected override void InternalDecodeFromCBORObject(CBORObject messageObject)
        {
            if (messageObject.Count != 4) throw new CoseException("Invalid Sign1 structure");

            if (messageObject[0].Type == CBORType.ByteString) {
                if (messageObject[0].GetByteString().Length == 0) ProtectedMap = CBORObject.NewMap();
                else {
                    ProtectedBytes = messageObject[0].GetByteString();
                    ProtectedMap = CBORObject.DecodeFromBytes(ProtectedBytes);
                    if (ProtectedMap.Count == 0) ProtectedBytes = new byte[0];
                }
            }
            else throw new CoseException("Invalid Sign1 structure");

            if (messageObject[1].Type == CBORType.Map) {
                UnprotectedMap = messageObject[1];
            }
            else throw new CoseException("Invalid Sign1 structure");

            if (messageObject[2].Type == CBORType.ByteString) rgbContent = messageObject[2].GetByteString();
            else if (!messageObject[2].IsNull) throw new CoseException("Invalid Sign1 structure");

            if (messageObject[3].Type == CBORType.ByteString) _rgbSignature = messageObject[3].GetByteString();
            else throw new CoseException("Invalid Sign1 structure");
        }
        #endregion

        public override CBORObject Encode()
        {
            CBORObject obj;

            obj = CBORObject.NewArray();

            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                obj.Add(ProtectedMap.EncodeToBytes());
            }
            else obj.Add(new byte[0]);

            ProtectedBytes = obj[0].GetByteString();

            ProcessCounterSignatures();

            if ((UnprotectedMap == null) || (UnprotectedMap.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(UnprotectedMap); // Add unprotected attributes

            obj.Add(rgbContent);

                PerformSignature();

            obj.Add(_rgbSignature);
            return obj;
        }

        private OneKey _keyToSign;
        private byte[] _rgbSignature;
        private string _context = "Signature1";

        public void AddSigner(OneKey key, CBORObject algorithm = null)
        {
            if (algorithm != null) AddAttribute(HeaderKeys.Algorithm, algorithm, UNPROTECTED);
            if (key.ContainsName(CoseKeyKeys.KeyIdentifier)) AddAttribute(HeaderKeys.KeyId, key[CoseKeyKeys.KeyIdentifier], UNPROTECTED);

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "sig") throw new CoseException("Key cannot be used for encrytion");
            }

            if (key.ContainsName(CoseKeyKeys.Key_Operations)) {
                CBORObject usageObject = key[CoseKeyKeys.Key_Operations];
                bool validUsage = false;

                if (usageObject.Type != CBORType.Array) throw new CoseException("key_ops is incorrectly formed");
                for (int i = 0; i < usageObject.Count; i++) {
                    switch (usageObject[i].AsString()) {
                    case "encrypt":
                    case "keywrap":
                        validUsage = true;
                        break;
                    }
                }
                if (!validUsage) throw new CoseException("Key cannot be used for encryption");
            }

            _keyToSign = key;
        }

        public void Sign(OneKey privateKey)
        {
            AddSigner(privateKey);
            PerformSignature();
        }

        public void PerformSignature()
        {
            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                byte[] rgb = ProtectedMap.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            if (_rgbSignature == null) {
                CBORObject signObj = CBORObject.NewArray();
                signObj.Add(_context);
                signObj.Add(cborProtected);
                signObj.Add(ExternalData); // External AAD
                signObj.Add(rgbContent);

                _rgbSignature = _Sign(toBeSigned());

#if FOR_EXAMPLES
                m_toBeSigned = signObj.EncodeToBytes();
#endif
            }
        }

        private byte[] toBeSigned()
        {
            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                byte[] rgb = ProtectedMap.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            CBORObject signObj = CBORObject.NewArray();
            signObj.Add(_context);
            signObj.Add(cborProtected);
            signObj.Add(ExternalData); // External AAD
            signObj.Add(rgbContent);

#if FOR_EXAMPLES
            m_toBeSigned = signObj.EncodeToBytes();
#endif

            return signObj.EncodeToBytes();
        }

        private byte[] _Sign(byte[] bytesToBeSigned)
        {
            CBORObject alg ; // Get the set algorithm or infer one

            if (rgbContent == null) throw new CoseException("No Content Specified");

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg == null) {
                if (_keyToSign[CoseKeyKeys.KeyType].Type == CBORType.Number) {
                    switch ((GeneralValuesInt) _keyToSign[CoseKeyKeys.KeyType].AsInt32()) {
                    case GeneralValuesInt.KeyType_RSA:
                        alg = AlgorithmValues.RSA_PSS_256;
                        break;

                    case GeneralValuesInt.KeyType_EC2:
                        if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.Number) {
                            switch ((GeneralValuesInt) _keyToSign[CoseKeyParameterKeys.EC_Curve].AsInt32()) {
                            case GeneralValuesInt.P256:
                                alg = AlgorithmValues.ECDSA_256;
                                break;

                            case GeneralValuesInt.P521:
                                alg = AlgorithmValues.ECDSA_512;
                                break;

                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.TextString) {
                            switch (_keyToSign[CoseKeyParameterKeys.EC_Curve].AsString()) {
                            case "P-384":
                                alg = CBORObject.FromObject("ES384");
                                break;

                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else throw new CoseException("Curve is incorrectly encoded");
                        break;

                    case GeneralValuesInt.KeyType_OKP:
                        if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.Number) {
                            switch ((GeneralValuesInt)_keyToSign[CoseKeyParameterKeys.EC_Curve].AsInt32()) {
                            case GeneralValuesInt.Ed25519:
                                alg = AlgorithmValues.EdDSA;
                                break;

                            case GeneralValuesInt.Ed448:
                                alg = AlgorithmValues.EdDSA;
                                break;

                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.TextString) {
                            switch (_keyToSign[CoseKeyParameterKeys.EC_Curve].AsString()) {
                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else
                            throw new CoseException("Curve is incorrectly encoded");

                        break;

                    default:
                        throw new CoseException("Unknown or unsupported key type " + _keyToSign.AsString("kty"));
                    }
                }
                else if (_keyToSign[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                    throw new CoseException("Unknown or unsupported key type " + _keyToSign[CoseKeyKeys.KeyType].AsString());
                }
                else throw new CoseException("Key type is not correctly encoded");
                UnprotectedMap.Add(HeaderKeys.Algorithm, alg);
            }

            IDigest digest = null;
            IDigest digest2 = null;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "ES384":
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case "HSS-LMS":
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.RSA_PSS_256:
                    digest = new Sha256Digest();
                    digest2 = new Sha256Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.RSA_PSS_384:
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_512:
                case AlgorithmValuesInt.RSA_PSS_512:
                    digest = new Sha512Digest();
                    digest2 = new Sha512Digest();
                    break;

                case AlgorithmValuesInt.EdDSA:
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "HSS-LMS":
                    HashSig sig = new HashSig(_keyToSign[CoseKeyParameterKeys.Lms_Private].AsString());
                    byte[] signBytes = sig.Sign(bytesToBeSigned);
                    
                    _keyToSign.Replace(CoseKeyParameterKeys.Lms_Private, CBORObject.FromObject(sig.PrivateKey));
                    return signBytes;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_384:
                case AlgorithmValuesInt.RSA_PSS_512: {
                    PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                    RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ),
                        _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                    ParametersWithRandom param = new ParametersWithRandom(prv, GetPRNG());

                    signer.Init(true, param);
                    signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                    return signer.GenerateSignature();
                }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512: {
                    CBORObject privateKeyD = _keyToSign[CoseKeyParameterKeys.EC_D];
                    if (privateKeyD == null) throw new CoseException("Private key required to sign");

                    SecureRandom random = GetPRNG();

                    digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                    byte[] digestedMessage = new byte[digest.GetDigestSize()];
                    digest.DoFinal(digestedMessage, 0);

                    X9ECParameters p = _keyToSign.GetCurve();
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                    ECPrivateKeyParameters privKey =
                        new ECPrivateKeyParameters("ECDSA", ConvertBigNum(privateKeyD), parameters);
                    ParametersWithRandom param = new ParametersWithRandom(privKey, random);

                    ECDsaSigner ecdsa = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
                    ecdsa.Init(true, param);

                    BigInteger[] sig = ecdsa.GenerateSignature(digestedMessage);

                    byte[] r = sig[0].ToByteArrayUnsigned();
                    byte[] s = sig[1].ToByteArrayUnsigned();

                    int cbR = (p.Curve.FieldSize + 7) / 8;

                    byte[] sigs = new byte[cbR * 2];
                    Array.Copy(r, 0, sigs, cbR - r.Length, r.Length);
                    Array.Copy(s, 0, sigs, cbR + cbR - s.Length, s.Length);

                    return sigs;
                }

#if true
                case AlgorithmValuesInt.EdDSA: {
                        ISigner eddsa;
                    if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed25519)) {
                        Ed25519PrivateKeyParameters privKey =
                            new Ed25519PrivateKeyParameters(_keyToSign[CoseKeyParameterKeys.OKP_D].GetByteString(), 0);
                        eddsa = new Ed25519Signer();
                        eddsa.Init(true, privKey);
                    }
                    else if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed448)) {
                        Ed448PrivateKeyParameters privKey =
                            new Ed448PrivateKeyParameters(_keyToSign[CoseKeyParameterKeys.OKP_D].GetByteString(), 0);
                        eddsa = new Ed448Signer(new byte[0]);
                        eddsa.Init(true, privKey);
                    }
                    else {
                        throw new CoseException("Unrecognized curve");
                    }


                    eddsa.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);

                    return eddsa.GenerateSignature();
                }
#endif

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        public bool Validate(OneKey signerKey)
        {
            CBORObject alg; // Get the set algorithm or infer one

            byte[] bytesToBeSigned = toBeSigned();

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg == null) {
                throw new CoseException("No algorithm specified");
            }

            IDigest digest = null;
            IDigest digest2 = null;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "ES384":
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case "HSS-LMS":
                    break;

                default:
                    throw new CoseException("Unknown signature algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.RSA_PSS_256:
                    digest = new Sha256Digest();
                    digest2 = new Sha256Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.RSA_PSS_384:
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_512:
                case AlgorithmValuesInt.RSA_PSS_512:
                    digest = new Sha512Digest();
                    digest2 = new Sha512Digest();
                    break;

                case AlgorithmValuesInt.EdDSA:
                    break;

                default:
                    throw new CoseException("Unknown signature algorithm");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "HSS-LMS":
                    return HashSig.Validate(bytesToBeSigned,
                                            signerKey[CoseKeyParameterKeys.Lms_Public].GetByteString(),
                                            _rgbSignature);

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_384:
                case AlgorithmValuesInt.RSA_PSS_512: {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(signerKey.AsBigInteger(CoseKeyParameterKeys.RSA_n), signerKey.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, GetPRNG());

                        signer.Init(false, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.VerifySignature(_rgbSignature);
                    }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512: {

                        digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        byte[] digestedMessage = new byte[digest.GetDigestSize()];
                        digest.DoFinal(digestedMessage, 0);

                        X9ECParameters p = signerKey.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPoint point = signerKey.GetPoint();
                        ECPublicKeyParameters param = new ECPublicKeyParameters(point, parameters);

                        ECDsaSigner ecdsa = new ECDsaSigner();
                        ecdsa.Init(false, param);

                        BigInteger r = new BigInteger(1, _rgbSignature, 0, _rgbSignature.Length / 2);
                        BigInteger s = new BigInteger(1, _rgbSignature, _rgbSignature.Length / 2, _rgbSignature.Length / 2);
                        return ecdsa.VerifySignature(digestedMessage, r, s);
                    }

#if true
                case AlgorithmValuesInt.EdDSA: {
                    ISigner eddsa;
                    if (signerKey[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed25519)) {
                        Ed25519PublicKeyParameters privKey =
                            new Ed25519PublicKeyParameters(signerKey[CoseKeyParameterKeys.OKP_X].GetByteString(), 0);
                        eddsa = new Ed25519Signer();
                        eddsa.Init(false, privKey);
                    }
                    else if (signerKey[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed448)) {
                        Ed448PublicKeyParameters privKey =
                            new Ed448PublicKeyParameters(signerKey[CoseKeyParameterKeys.OKP_X].GetByteString(), 0);
                        eddsa = new Ed448Signer(new byte[0]);
                        eddsa.Init(false, privKey);
                    }
                    else {
                        throw new CoseException("Unrecognized curve");
                    }

                    eddsa.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                    return eddsa.VerifySignature(_rgbSignature);
                }
#endif

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        private BigInteger ConvertBigNum(CBORObject cbor)
        {
            byte[] rgb = cbor.GetByteString();
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new BigInteger(rgb2);
        }

#if FOR_EXAMPLES
        byte[] m_toBeSigned = null;
        public byte[] GetToBeSigned() { return m_toBeSigned; }
#endif
    }
}
