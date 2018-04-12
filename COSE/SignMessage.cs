using System;
using System.Collections.Generic;
using System.Linq;

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
    public class SignMessage : Message
    {
        List<Signer> signerList = new List<Signer>();

        public SignMessage(bool fEmitTag = true, bool fEmitContent = true) : base(fEmitTag, fEmitContent)
        {
            m_tag = Tags.Sign;
        }

        public List<Signer> SignerList { get { return signerList; } }

        public void AddSigner(Signer sig)
        {
            signerList.Add(sig);
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

        virtual public void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 4) throw new CoseException("Invalid SignMessage structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                ProtectedBytes = obj[0].GetByteString();
                if (ProtectedBytes.Length == 0) ProtectedMap = CBORObject.NewMap();
                else {
                    ProtectedMap = CBORObject.DecodeFromBytes(ProtectedBytes);
                    if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid SignMessage structure");
                    if (ProtectedMap.Count == 0) ProtectedBytes = new byte[0];
                }
            }
            else {
                throw new CoseException("Invalid SignMessage structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid SignMessage structure");

            // Plain Text
            if (obj[2].Type == CBORType.ByteString) rgbContent = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid SignMessage structure");
            }

            // Signers
            if (obj[3].Type != CBORType.Array) throw new CoseException("Invalid SignMessage structure");
            // An array of signers to be processed
            for (int i = 0; i < obj[3].Count; i++) {
                Signer recip = new Signer();
                recip.DecodeFromCBORObject(obj[3][i]);
                signerList.Add(recip);
            }

        }

        public override CBORObject Encode()
        {
            CBORObject obj;
            byte[] rgbProtected;

            obj = CBORObject.NewArray();

            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                rgbProtected = ProtectedMap.EncodeToBytes();
                obj.Add(rgbProtected);
            }
            else {
                rgbProtected = new byte[0];
                obj.Add(rgbProtected);
            }

            if (m_counterSignerList.Count() != 0) {
                if (m_counterSignerList.Count() == 1) {
                    AddAttribute(HeaderKeys.CounterSignature, m_counterSignerList[0].EncodeToCBORObject(rgbProtected, rgbContent), UNPROTECTED);
                }
                else {
                    foreach (CounterSignature sig in m_counterSignerList) {
                        sig.EncodeToCBORObject(rgbProtected, rgbContent);
                    }
                }
            }

            if ((UnprotectedMap == null) || (UnprotectedMap.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(UnprotectedMap); // Add unprotected attributes

            obj.Add(rgbContent);

            if ((signerList.Count == 1) && !m_forceArray) {
                CBORObject recipient = signerList[0].EncodeToCBORObject(obj[0].EncodeToBytes(), rgbContent);

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (signerList.Count > 0) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToCBORObject(rgbProtected, rgbContent));
                }
                obj.Add(signers);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }

        public bool Validate(Signer signer)
        {
            foreach (Signer x in signerList) {
                if (x == signer) {
                    return signer.Validate(rgbContent, ProtectedBytes);
                }
            }

            throw new Exception("Signer is not for this message");
        }

    }

    public class Signer : Attributes
    {
        private OneKey _keyToSign;
        private byte[] _rgbSignature = null;
        protected string context = "Signature";

        public Signer(OneKey key, CBORObject algorithm = null)
        {
            if (algorithm != null) AddAttribute(HeaderKeys.Algorithm, algorithm, UNPROTECTED);
            if (key.ContainsName(CoseKeyKeys.KeyIdentifier)) AddAttribute(HeaderKeys.KeyId, key[CoseKeyKeys.KeyIdentifier], UNPROTECTED);

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "sig") throw new Exception("Key cannot be used for encrytion");
            }

            if (key.ContainsName(CoseKeyKeys.Key_Operations)) {
                CBORObject usageObject = key[CoseKeyKeys.Key_Operations];
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
                if (!validUsage) throw new Exception("Key cannot be used for encryption");
            }

            _keyToSign = key;
        }

        public Signer()
        {

        }

        public void SetKey(OneKey key)
        {
            _keyToSign = key;
        }

        public void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Type != CBORType.Array) throw new CoseException("Invalid Signer structure");

            if (obj.Count != 3) throw new CoseException("Invalid Signer structure");

            if (obj[0].Type == CBORType.ByteString) {
                if (obj[0].GetByteString().Length == 0) {
                    ProtectedMap = CBORObject.NewMap();
                    ProtectedBytes = new byte[0];
                }
                else {
                    ProtectedBytes = obj[0].GetByteString();
                    ProtectedMap = CBORObject.DecodeFromBytes(ProtectedBytes);
                    if (ProtectedMap.Count == 0) ProtectedBytes = new byte[0];
                }
            }
            else throw new CoseException("Invalid Signer structure");

            if (obj[1].Type == CBORType.Map) {
                UnprotectedMap = obj[1];
            }
            else throw new CoseException("Invalid Signer structure");

            if (obj[2].Type == CBORType.ByteString) _rgbSignature = obj[2].GetByteString();
            else throw new CoseException("Invalid Signer structure");
        }

        public CBORObject EncodeToCBORObject()
        {
            if (_rgbSignature == null) {
                throw new Exception("Must be signed already to use this function call");
            }
            return EncodeToCBORObject(null, null);
        }

        public CBORObject EncodeToCBORObject(byte[] bodyAttributes, byte[] body)
        {
            CBORObject obj = CBORObject.NewArray();

            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                byte[] rgb = ProtectedMap.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }
            obj.Add(cborProtected);

            if ((UnprotectedMap == null)) obj.Add(CBORObject.NewMap());
            else obj.Add(UnprotectedMap); // Add unprotected attributes

            if (_rgbSignature == null) {
                _rgbSignature = Sign(toBeSigned(body, bodyAttributes));
            }
            obj.Add(_rgbSignature);
            return obj;
        }

        private byte[] toBeSigned(byte[] rgbContent, byte[] bodyAttributes)
        {
            CBORObject cborProtected = CBORObject.FromObject(new byte[0]);
            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                byte[] rgb = ProtectedMap.EncodeToBytes();
                cborProtected = CBORObject.FromObject(rgb);
            }

            CBORObject signObj = CBORObject.NewArray();
            signObj.Add(context);
            signObj.Add(bodyAttributes);
            signObj.Add(cborProtected);
            signObj.Add(ExternalData);
            signObj.Add(rgbContent);

#if FOR_EXAMPLES
            m_toBeSigned = signObj.EncodeToBytes();
#endif
            return signObj.EncodeToBytes();
        }

        private byte[] Sign(byte[] bytesToBeSigned)
        {
            CBORObject alg; // Get the set algorithm or infer one

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

                            case GeneralValuesInt.P384:
                                alg = AlgorithmValues.ECDSA_384;
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
                            default:
                                throw new CoseException("Unknown curve");
                            }
                        }
                        else
                            throw new CoseException("Curve is incorrectly encoded");

                        break;

                    case GeneralValuesInt.KeyType_OKP:
                        if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Type == CBORType.Number) {
                            switch ((GeneralValuesInt) _keyToSign[CoseKeyParameterKeys.EC_Curve].AsInt32()) {
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
                        throw new Exception("Unknown or unsupported key type " + _keyToSign.AsString("kty"));
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
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                default:
                    throw new Exception("Unknown signature algorithm");
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
                    throw new CoseException("Unknown signature algorith");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384":
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();

                    }

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.RSA_PSS_256:
                case AlgorithmValuesInt.RSA_PSS_512:
                    {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.GenerateSignature();
                    }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512:
                    {
                        SecureRandom random = Message.GetPRNG();

                        digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        byte[] digestedMessage = new byte[digest.GetDigestSize()];
                        digest.DoFinal(digestedMessage, 0);

                        X9ECParameters p = _keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPrivateKeyParameters privKey = new ECPrivateKeyParameters("ECDSA", ConvertBigNum(_keyToSign[CoseKeyParameterKeys.EC_D]), parameters);
                        ParametersWithRandom param = new ParametersWithRandom(privKey, random);

                        ECDsaSigner ecdsa = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
                        ecdsa.Init(true, param);

                        BigInteger[] sig = ecdsa.GenerateSignature(digestedMessage);
                        byte[] r = sig[0].ToByteArrayUnsigned();
                        byte[] s = sig[1].ToByteArrayUnsigned();

                        int cbR = (p.Curve.FieldSize+7)/8;

                        byte[] sigs = new byte[cbR*2];
                        Array.Copy(r, 0, sigs, cbR-r.Length, r.Length);
                        Array.Copy(s, 0, sigs, cbR+cbR-s.Length, s.Length);

                        return sigs;
                    }

                case AlgorithmValuesInt.EdDSA: {
                    EdDSA eddsa;
                    if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed25519)) {
                        eddsa = new EdDSA25517();
                    }
                    else if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed448)) {
                        eddsa = new EdDSA448();
                    }
                    else {
                        throw new CoseException("Unrecognized curve");
                    }
                    EdDSAPoint publicKey = eddsa.DecodePoint(_keyToSign[CoseKeyParameterKeys.OKP_X].GetByteString());
                    byte[] sig = eddsa.Sign(publicKey, _keyToSign[CoseKeyParameterKeys.OKP_D].GetByteString(), bytesToBeSigned);
                    return sig;
                }

                default:
                    throw new CoseException("Unknown Algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        public bool Validate(byte[] content, byte[] msgAttributes)
        {
            CBORObject alg; // Get the set algorithm or infer one

            byte[] bytesToBeSigned = toBeSigned(content, msgAttributes);

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg == null) {
                throw new Exception("No Signature algorithm known");
            }

            IDigest digest = null;
            IDigest digest2 = null;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384":
                    digest = new Sha384Digest();
                    digest2 = new Sha384Digest();
                    break;

                default:
                    throw new Exception("Unknown signature algorithm");
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
                    throw new CoseException("Unknown signature algorith");
                }
            }
            else throw new CoseException("Algorthm incorrectly encoded");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "PS384": {
                        PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetByteLength());

                        RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(_keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_n), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_e), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_d), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_p), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_q), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dP), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), _keyToSign.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

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
                        ParametersWithRandom param = new ParametersWithRandom(prv, Message.GetPRNG());

                        signer.Init(true, param);
                        signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        return signer.VerifySignature(_rgbSignature);
                    }

                case AlgorithmValuesInt.ECDSA_256:
                case AlgorithmValuesInt.ECDSA_384:
                case AlgorithmValuesInt.ECDSA_512: {
                        digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                        byte[] digestedMessage = new byte[digest.GetDigestSize()];
                        digest.DoFinal(digestedMessage, 0);

                        X9ECParameters p = _keyToSign.GetCurve();
                        ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                        ECPoint point = _keyToSign.GetPoint();
                        ECPublicKeyParameters param = new ECPublicKeyParameters(point, parameters);

                        ECDsaSigner ecdsa = new ECDsaSigner();
                        ecdsa.Init(false, param);

                        BigInteger r = new BigInteger(1, _rgbSignature, 0, _rgbSignature.Length/2);
                        BigInteger s = new BigInteger(1, _rgbSignature, _rgbSignature.Length/2, _rgbSignature.Length/2);
                        return ecdsa.VerifySignature(digestedMessage, r, s);
                    }

                case AlgorithmValuesInt.EdDSA: {
                    EdDSA eddsa;
                    if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed25519)) {
                        eddsa = new EdDSA25517();
                    }
                    else if (_keyToSign[CoseKeyParameterKeys.EC_Curve].Equals(GeneralValues.Ed448)) {
                        eddsa = new EdDSA448();
                    }
                    else {
                        throw new CoseException("Unrecognized curve");
                    }
                    byte[] publicKey = _keyToSign[CoseKeyParameterKeys.OKP_X].GetByteString();
                    return eddsa.Verify(publicKey, bytesToBeSigned, _rgbSignature);
                }

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

    public class CounterSignature : Signer
    {
        private Message m_msgToSign;
        private Signer m_signerToSign;

        public CounterSignature(OneKey key, CBORObject algorithm = null) : base(key, algorithm)
        {
            context = "CounterSignature";
        }

        public void SetObject(Message msg)
        {
            m_msgToSign = msg;    
        }

        public void SetObject(Signer signer)
        {
            m_signerToSign = signer;
        }

        new public CBORObject EncodeToCBORObject()
        {
            CBORObject cborBodyAttributes = null;
            byte[] rgbBody = null;

            if (m_msgToSign != null) {
                if (m_msgToSign.GetType() == typeof(EncryptMessage)) {
                    EncryptMessage msg = (EncryptMessage) m_msgToSign;
                    msg.Encrypt();
                    CBORObject obj = msg.EncodeToCBORObject();
                    if (obj[1].Type != CBORType.ByteString) throw new Exception("Internal error");
                    if (obj[3].Type != CBORType.ByteString) throw new Exception("Internal error");
                    rgbBody = obj[3].GetByteString();
                    cborBodyAttributes = obj[1];
                }
            }
            else if (m_signerToSign != null) {
               CBORObject obj = m_signerToSign.EncodeToCBORObject();
            }


            return base.EncodeToCBORObject(cborBodyAttributes.GetByteString(), rgbBody);
        }
    }
}
