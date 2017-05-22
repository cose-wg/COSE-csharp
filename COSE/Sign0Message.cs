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

        virtual public void DecodeFromCBORObject(CBORObject messageObject)
        {
            if (messageObject.Count != 4) throw new CoseException("Invalid Sign1 structure");

            if (messageObject[0].Type == CBORType.ByteString) {
                if (messageObject[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else {
                    _rgbProtected = messageObject[0].GetByteString();
                    objProtected = CBORObject.DecodeFromBytes(_rgbProtected);
                    if (objProtected.Count == 0) _rgbProtected = new byte[0];
                }
            }
            else throw new CoseException("Invalid Sign1 structure");

            if (messageObject[1].Type == CBORType.Map) {
                objUnprotected = messageObject[1];
            }
            else throw new CoseException("Invalid Sign1 structure");

            if (messageObject[2].Type == CBORType.ByteString) rgbContent = messageObject[2].GetByteString();
            else if (!messageObject[2].IsNull) throw new CoseException("Invalid Sign1 structure");

            if (messageObject[3].Type == CBORType.ByteString) _rgbSignature = messageObject[3].GetByteString();
            else throw new CoseException("Invalid Sign1 structure");
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            obj = CBORObject.NewArray();

            if ((objProtected != null) && (objProtected.Count > 0)) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(new byte[0]);

            if ((objUnprotected == null) || (objUnprotected.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(objUnprotected); // Add unprotected attributes

            obj.Add(rgbContent);

                PerformSignature();

            obj.Add(_rgbSignature);
            return obj;
        }

        private OneKey _keyToSign;
        private byte[] _rgbSignature;
        protected string _context = "Signature1";

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
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            if (_rgbSignature == null) {
                CBORObject signObj = CBORObject.NewArray();
                signObj.Add(_context);
                signObj.Add(cborProtected);
                signObj.Add(externalData); // External AAD
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
            if ((objProtected != null) && (objProtected.Count > 0)) {
                byte[] rgb = objProtected.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            CBORObject signObj = CBORObject.NewArray();
            signObj.Add(_context);
            signObj.Add(cborProtected);
            signObj.Add(externalData); // External AAD
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
                        alg = CBORObject.FromObject("PS256");
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

                    default:
                        throw new CoseException("Unknown or unsupported key type " + _keyToSign.AsString("kty"));
                    }
                }
                else if (_keyToSign[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                    throw new CoseException("Unknown or unsupported key type " + _keyToSign[CoseKeyKeys.KeyType].AsString());
                }
                else throw new CoseException("Key type is not correctly encoded");
                objUnprotected.Add(HeaderKeys.Algorithm, alg);
            }

            IDigest digest;
            IDigest digest2;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "ES384":
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
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
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_512:
                case AlgorithmValuesInt.RSA_PSS_512:
                    digest = new Sha512Digest();
                    digest2 = new Sha512Digest();
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384":
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();
                    }

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_512:
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();
                    }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512:
                    {
                        CBORObject privateKeyD = _keyToSign[CoseKeyParameterKeys.EC_D];
                        if (privateKeyD == null) throw new CoseException("Private key required to sign");

                        SecureRandom random = GetPRNG();

                        digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        byte[] digestedMessage = new byte[digest.GetDigestSize()];
                        digest.DoFinal(digestedMessage, 0);

                        X9ECParameters p = _keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(privateKeyD), parameters);
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

            IDigest digest;
            IDigest digest2;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "ES384":
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
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
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                case AlgorithmValuesInt.ECDSA_512:
                case AlgorithmValuesInt.RSA_PSS_512:
                    digest = new Sha512Digest();
                    digest2 = new Sha512Digest();
                    break;

                default:
                    throw new CoseException("Unknown signature algorithm");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384": {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.VerifySignature(_rgbSignature);
                    }

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_512: {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
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

                    case AlgorithmValuesInt.EdDSA:
                        throw new CoseException(("NYI - Ed signatures"));

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
