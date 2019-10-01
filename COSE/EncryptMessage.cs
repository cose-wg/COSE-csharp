using System;
using System.Collections.Generic;
using System.Linq;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

using System.Diagnostics;

namespace Com.AugustCellars.COSE
{

    public enum RecipientType
    {
        direct=1, keyAgree=2, keyTransport=3, keyWrap=4, keyAgreeDirect=5, keyTransportAndWrap=6, password=7
    }

    public class Recipient : EncryptCommon
    {
        private OneKey m_key;
        private OneKey m_senderKey;
        private readonly List<Recipient> _recipientList = new List<Recipient>();

        public Recipient(OneKey key, CBORObject algorithm = null) : base(true, true, "Rec_Recipient")
        {
            if (algorithm != null) {
                if (algorithm.Type == CBORType.TextString) {
                    switch (algorithm.AsString()) {
                    case "A128GCMKW":
                    case "A192GCMKW":
                    case "A256GCMKW":
                        if (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Invalid Parameter");
                        break;


                    case "PBES2-HS256+A128KW":
                    case "PBES2-HS256+A192KW":
                    case "PBES-HS256+A256KW":
                        if (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Invalid Parameter");
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else if (algorithm.Type == CBORType.Integer) {
                    switch ((AlgorithmValuesInt) algorithm.AsInt32()) {
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    case AlgorithmValuesInt.Direct_HKDF_AES_128:
                    case AlgorithmValuesInt.Direct_HKDF_AES_256:
                        if (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) {
                            throw new CoseException("Invalid parameters");
                        }
                        break;


                    case AlgorithmValuesInt.RSA_OAEP:
                    case AlgorithmValuesInt.RSA_OAEP_256:
                    case AlgorithmValuesInt.RSA_OAEP_512:
                        if (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_RSA)) {
                            throw new CoseException("Invalid Parameter");
                        }
                        break;

                    case AlgorithmValuesInt.AES_KW_128:
                    case AlgorithmValuesInt.AES_KW_192:
                    case AlgorithmValuesInt.AES_KW_256:
                        if ((key != null) && (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet))) {
                            throw new CoseException("Invalid Parameter");
                        }
                        break;

                    case AlgorithmValuesInt.DIRECT: // Direct encryption mode
                        if (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) {
                            throw new CoseException("Invalid parameters");
                        }                
                        break;

                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_128:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_192:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_256:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_128:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_192:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_256:
                        if ((!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) &&
                            (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP))) {
                            throw new CoseException("Invalid Parameter");
                        }
                        break;

                    case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_512:
#if DEBUG
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_512:
#endif // DEBUG
                        if ((!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) &&
                            (!key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP))) {
                            throw new CoseException("Invalid Parameters");
                        }
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else throw new CoseException("Algorithm incorrectly encoded");

                m_key = key;
                AddAttribute(HeaderKeys.Algorithm, algorithm, UNPROTECTED);
            }
            else {
                if (key[CoseKeyKeys.KeyType].Type == CBORType.Integer) {
                    switch ((GeneralValuesInt) key[CoseKeyKeys.KeyType].AsInt32()) {
                    case GeneralValuesInt.KeyType_Octet:
                        switch (key.AsBytes(CoseKeyParameterKeys.Octet_k).Length) {
                        case 128 / 8:
                            algorithm = AlgorithmValues.AES_KW_128;
                            break;

                        case 192 / 8:
                            algorithm = AlgorithmValues.AES_KW_192;
                            break;

                        case 256 / 8:
                            algorithm = AlgorithmValues.AES_KW_256;
                            break;

                        default:
                            throw new CoseException("Key size does not match any algorthms");
                        }
                        break;

                    case GeneralValuesInt.KeyType_RSA:
                        algorithm = AlgorithmValues.RSA_OAEP_256;
                        break;

                    case GeneralValuesInt.KeyType_EC2:
                        algorithm =  AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128;
                        break;
                    }
                    AddAttribute(HeaderKeys.Algorithm, algorithm, UNPROTECTED);
                    m_key = key;
                }
                else if (key[CoseKeyKeys.KeyType].Type == CBORType.TextString) {
                    throw new CoseException("Unsupported key type");
                }
                else throw new CoseException("Invalid encoding for key type");
            }

            if (key != null) {
                if (key.ContainsName("use")) {
                    string usage = key.AsString("use");
                    if (usage != "enc") throw new CoseException("Key cannot be used for encrytion");
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

                if (key[CoseKeyKeys.KeyIdentifier] != null) AddAttribute(HeaderKeys.KeyId, key[CoseKeyKeys.KeyIdentifier], UNPROTECTED);
            }
        }

        public Recipient() : base(true, true, "Rec_Recipient")
        {
        }

        public List<Recipient> RecipientList
        {
            get { return _recipientList; }
        }

        public RecipientType recipientType {
            get {
                CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
                if (alg == null) throw new CoseException("No recipient algorithm set");
                if (alg.Type == CBORType.TextString) {
                    throw new CoseException("Unsupported algorithm " + alg.AsString());
                }

                switch ((AlgorithmValuesInt) alg.AsInt32())
                {
                    case AlgorithmValuesInt.DIRECT:
                    case AlgorithmValuesInt.Direct_HKDF_AES_128:
                    case AlgorithmValuesInt.Direct_HKDF_AES_256:
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                        return RecipientType.direct;

                    case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_512:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_512:
                        return RecipientType.keyAgreeDirect;

                    case AlgorithmValuesInt.AES_KW_128:
                    case AlgorithmValuesInt.AES_KW_192:
                    case AlgorithmValuesInt.AES_KW_256:
                        return RecipientType.keyWrap;

                    case AlgorithmValuesInt.RSA_OAEP:
                    case AlgorithmValuesInt.RSA_OAEP_256:
                    case AlgorithmValuesInt.RSA_OAEP_512:
                        return RecipientType.keyTransport;

                    default:
                        return RecipientType.keyAgree;
                }
            }
        }

        public void AddRecipient(Recipient recipient)
        {
            recipient.SetContext("Enc_Recipient");
            _recipientList.Add(recipient);
        }



        #region Decoders


        protected override void InternalDecodeFromCBORObject(CBORObject obj)
        {
            throw new CoseException("Internal Error - Recipient.InternalDecodeFromObject should never be called.");
        }

        public void DecodeFromCBORObject(CBORObject obj)
        {
            if ((obj.Count != 3) && (obj.Count != 4)) throw new CoseException("Invalid Encrypt structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                if (obj[0].GetByteString().Length == 0) ProtectedMap = CBORObject.NewMap();
                else ProtectedMap = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid Encrypt structure");
            }
            else {
                throw new CoseException("Invalid Encrypt structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid Encrypt structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) RgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encrypt structure");
            }

            // Recipients
            if (obj.Count == 4) {
                if (obj[3].Type == CBORType.Array) {
                    // An array of recipients to be processed
                    for (int i = 0; i < obj[3].Count; i++) {
                        Recipient recip = new Recipient();
                        recip.DecodeFromCBORObject(obj[3][i]);
                        _recipientList.Add(recip);
                    }
                }
                else throw new CoseException("Invalid Encrypt structure");
            }
        }
#endregion

        public byte[] Decrypt(int cbitCEK, CBORObject algCEK, Recipient recipientIn)
        {
            byte[] CEK = null;
            CBORObject algKEK = FindAttribute(HeaderKeys.Algorithm);
            int cbitKEK = GetKeySize(algKEK);

            foreach (Recipient r in _recipientList) {
                if (r == recipientIn) {
                    CEK = r.Decrypt(cbitKEK, algKEK, recipientIn);
                    if (CEK == null) throw new CoseException("Internal Error");
                    return CEK;
                }
                else if (r._recipientList.Count > 0) {
                    CEK = r.Decrypt(cbitKEK, algKEK, recipientIn);
                    if (CEK != null) return CEK;        
                }
            }

            if (CEK == null) throw new CoseException("Recipient key not found");
            return null;
        }

        public byte[] Decrypt(int cbitCEK, CBORObject algCEK)
        {
            return Decrypt(m_key, cbitCEK, algCEK);
        }

        public byte[] Decrypt(OneKey key, int cbitCEK, CBORObject algCEK)
        {
            CBORObject alg = null;
            byte[] rgbSecret;
            byte[] rgbKey;

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (alg == null) return null;
            if (key == null) return null;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {

                case "A128GCMKW": return AES_GCM_KeyUnwrap(key, 128);
                case "A192GCMKW": return AES_GCM_KeyUnwrap(key, 192);
                case "A256GCMKW": return AES_GCM_KeyUnwrap(key, 256);

                case "PBES2-HS256+A128KW":
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 128 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 128, rgbKey);

                case "PBES2-HS256+A192KW":
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 192 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 192, rgbKey);

                case "PBES2-HS256+A256KW":
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), FindAttribute("p2s").GetByteString(), FindAttribute("p2c").AsInt32(), 256 / 8, new Sha256Digest());
                    return AES_KeyUnwrap(null, 256, rgbKey);

                }
            }
            else if (alg.Type == CBORType.Integer) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.DIRECT:
                    if (key[CoseKeyKeys.KeyType].AsInt32() != (int) GeneralValuesInt.KeyType_Octet) return null;
                    return key.AsBytes(CoseKeyParameterKeys.Octet_k);

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK, new Sha256Digest());

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK, new Sha512Digest());

                case AlgorithmValuesInt.Direct_HKDF_AES_128:
                case AlgorithmValuesInt.Direct_HKDF_AES_256:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF_AES(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK);

                case AlgorithmValuesInt.RSA_OAEP: return RSA_OAEP_KeyUnwrap(key, new Sha1Digest());
                case AlgorithmValuesInt.RSA_OAEP_256: return RSA_OAEP_KeyUnwrap(key, new Sha256Digest());
                case AlgorithmValuesInt.RSA_OAEP_512: return RSA_OAEP_KeyUnwrap(key, new Sha512Digest());

                case AlgorithmValuesInt.AES_KW_128: return AES_KeyUnwrap(key, 128);
                case AlgorithmValuesInt.AES_KW_192: return AES_KeyUnwrap(key, 192);
                case AlgorithmValuesInt.AES_KW_256: return AES_KeyUnwrap(key, 256);

                case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    rgbSecret = ECDH_GenerateSecret(key);
                    return HKDF(rgbSecret, cbitCEK, algCEK, new Sha256Digest());

                case AlgorithmValuesInt.ECDH_ES_HKDF_512:
                case AlgorithmValuesInt.ECDH_SS_HKDF_512:
                    rgbSecret = ECDH_GenerateSecret(key);
                    return HKDF(rgbSecret, cbitCEK, algCEK, new Sha512Digest());

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_128:
                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_128:
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = HKDF(rgbSecret, 128, AlgorithmValues.AES_KW_128, new Sha256Digest());
                    return AES_KeyUnwrap(null, 128, rgbKey);

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_192:
                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_192:
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = HKDF(rgbSecret, 192, AlgorithmValues.AES_KW_192, new Sha256Digest());
                    return AES_KeyUnwrap(null, 192, rgbKey);

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_256:
                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_256:
                    rgbSecret = ECDH_GenerateSecret(key);
                    rgbKey = HKDF(rgbSecret, 256, AlgorithmValues.AES_KW_256, new Sha256Digest());
                    return AES_KeyUnwrap(null, 256, rgbKey);

                default:
                    throw new CoseException("Algorithm not supported " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm is incorrectly encoded");

            return null;
        }

        override public CBORObject Encode()
        {
            CBORObject obj;

            if (RgbEncrypted == null) Encrypt();


            obj = CBORObject.NewArray();

            if (ProtectedMap.Count > 0) {
                obj.Add(ProtectedMap.EncodeToBytes());
            }
            else obj.Add(CBORObject.FromObject(new byte[0]));

            obj.Add(UnprotectedMap); // Add unprotected attributes

            if (RgbEncrypted == null) obj.Add(new byte[0]);
            else obj.Add(RgbEncrypted);      // Add ciphertext

            if ((_recipientList.Count == 1) && !m_forceArray) {
                CBORObject recipient = _recipientList[0].Encode();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (_recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in _recipientList) {
                    recipients.Add(key.Encode());
                }
                obj.Add(recipients);
            }
            else {
                // obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }

        public void Encrypt()
        {
            CBORObject alg;      // Get the algorithm that was set.
            byte[] rgbSecret;
            byte[] rgbKey = null;
            CBORObject objSalt;
            CBORObject objIterCount;

            alg = FindAttribute(HeaderKeys.Algorithm);

            if (_recipientList.Count> 0) {
                if (m_key != null) throw new CoseException("Can't mix nested recipients and fixed keys.");

                //  Determine if we are doing a direct encryption
                int recipientTypes = 0;

                foreach (Recipient key in _recipientList) {
                    switch (key.recipientType) {
                    case RecipientType.direct:
                    case RecipientType.keyAgreeDirect:
                        if ((recipientTypes & 1) != 0) throw new CoseException("It is not legal to have two direct recipients in a message");
                        recipientTypes |= 1;
                        rgbKey = key.GetKey(alg);
#if FOR_EXAMPLES
                        m_kek = rgbKey;
#endif
                        break;

                    default:
                        recipientTypes |= 2;
                        break;
                    }
                }

                if (recipientTypes == 3) throw new CoseException("It is not legal to mix direct and indirect recipients in a message");
            }

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                // case "dir":
                case "dir+kdf":
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    break;


                case "A128GCMKW": AES_GCM_KeyWrap(rgbKey, 128); break;
                case "A192GCMKW": AES_GCM_KeyWrap(rgbKey, 192); break;
                case "A256GCMKW": AES_GCM_KeyWrap(rgbKey, 256); break;

                case "PBES2-HS256+A128KW":
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddAttribute("p2s", objSalt, UNPROTECTED);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddAttribute("p2c", objIterCount, UNPROTECTED);
                    }
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), objSalt.GetByteString(), objIterCount.AsInt32(), 128 / 8, new Sha256Digest());
                    AES_KeyWrap(128, rgbKey);
                    break;

                case "PBES2-HS384+A192KW":
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddAttribute("p2s", objSalt, UNPROTECTED);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddAttribute("p2c", objIterCount, UNPROTECTED);
                    }
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), objSalt.GetByteString(), objIterCount.AsInt32(), 192 / 8, new Sha256Digest());
                    AES_KeyWrap(192, rgbKey);
                    break;

                case "PBES2-HS512+256KW":
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    objSalt = FindAttribute("p2s");
                    if (objSalt == null) {
                        byte[] salt = new byte[10];
                        s_PRNG.NextBytes(salt);
                        objSalt = CBORObject.FromObject(salt);
                        AddAttribute("p2s", objSalt, UNPROTECTED);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddAttribute("p2c", objIterCount, UNPROTECTED);
                    }
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), objSalt.GetByteString(), objIterCount.AsInt32(), 256 / 8, new Sha256Digest());
                    AES_KeyWrap(256, rgbKey);
                    break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else if (alg.Type == CBORType.Integer) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.DIRECT:
                case AlgorithmValuesInt.Direct_HKDF_AES_128:
                case AlgorithmValuesInt.Direct_HKDF_AES_256:
                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                case AlgorithmValuesInt.ECDH_ES_HKDF_512:
                case AlgorithmValuesInt.ECDH_SS_HKDF_512:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    break;

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_128:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 128, AlgorithmValues.AES_KW_128, new Sha256Digest());
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    AES_KeyWrap(128, rgbKey);
                    break;

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_192:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 192, AlgorithmValues.AES_KW_192, new Sha256Digest());
                    AES_KeyWrap(192, rgbKey);
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    break;

                case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_256:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    ECDH_GenerateEphemeral();
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 256, AlgorithmValues.AES_KW_256, new Sha256Digest());
                    AES_KeyWrap(256, rgbKey);
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    break;

                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_128:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorith");
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 128, AlgorithmValues.AES_KW_128, new Sha256Digest());
                    AES_KeyWrap(128, rgbKey);
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    break;

                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_192:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorith");
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 192, AlgorithmValues.AES_KW_192, new Sha256Digest());
                    AES_KeyWrap(192, rgbKey);
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    break;

                case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_256:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorith");
                    rgbSecret = ECDH_GenerateSecret(m_key);
                    rgbKey = HKDF(rgbSecret, 256, AlgorithmValues.AES_KW_256, new Sha256Digest());
                    AES_KeyWrap(256, rgbKey);
#if FOR_EXAMPLES
                    m_kek = rgbKey;
#endif
                    break;

                case AlgorithmValuesInt.RSA_OAEP:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    RSA_OAEP_KeyWrap(new Sha1Digest()); 
                    break;

                case AlgorithmValuesInt.RSA_OAEP_256: 
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    RSA_OAEP_KeyWrap(new Sha256Digest()); 
                    break;

                case AlgorithmValuesInt.RSA_OAEP_512:
                    if (rgbKey != null) throw new CoseException("Can't wrap around this algorithm");
                    RSA_OAEP_KeyWrap(new Sha512Digest());
                    break;

                case AlgorithmValuesInt.AES_KW_128: AES_KeyWrap(128, rgbKey); break;
                case AlgorithmValuesInt.AES_KW_192: AES_KeyWrap(192, rgbKey); break;
                case AlgorithmValuesInt.AES_KW_256: AES_KeyWrap(256, rgbKey); break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            foreach (Recipient key in _recipientList) {
                key.SetContent(rgbKey);
                key.Encrypt();
            }

            if (CounterSignerList.Count() != 0) {
                byte[] rgbProtected;
                if (ProtectedMap.Count > 0) rgbProtected = ProtectedMap.EncodeToBytes();
                else rgbProtected = new byte[0];
                if (CounterSignerList.Count() == 1) {
                    AddAttribute(HeaderKeys.CounterSignature, CounterSignerList[0].EncodeToCBORObject(rgbProtected, RgbEncrypted), UNPROTECTED);
                }
                else {
                    foreach (CounterSignature sig in CounterSignerList) {
                        sig.EncodeToCBORObject(rgbProtected, RgbEncrypted);
                    }
                }
            }

            if (CounterSigner1 != null) {
                byte[] rgbProtected;
                if (ProtectedMap.Count > 0) rgbProtected = ProtectedMap.EncodeToBytes();
                else rgbProtected = new byte[0];
                AddAttribute(HeaderKeys.CounterSignature0, CounterSigner1.EncodeToCBORObject(rgbProtected, RgbEncrypted), UNPROTECTED);
            }

        }

        public byte[] GetKey(CBORObject alg)
        {
            if (m_key == null) return null;

             //   CBORObject keyAlgorithm = m_key[HeaderKeys.Algorithm];
             //   if ((keyAlgorithm != null) && (!alg.Equals(keyAlgorithm))) throw new CoseException("Algorithm mismatch between message and key");
  
            //  Figure out how longer the needed key is:

            int cbitKey;
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {

                case "AES-CCM-128/64":
                case "AES-CMAC-128/64":
                    cbitKey = 128;
                    break;

                case "AES-CMAC-256/64":
                    cbitKey = 256;
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Integer) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_CCM_16_64_128:
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                case AlgorithmValuesInt.AES_CCM_16_128_128:
                case AlgorithmValuesInt.AES_CCM_64_128_128:
                case AlgorithmValuesInt.AES_KW_128:
                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_KW_192:
                    cbitKey = 192;
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                case AlgorithmValuesInt.ChaCha20_Poly1305:
                case AlgorithmValuesInt.AES_CCM_16_64_256:
                case AlgorithmValuesInt.AES_CCM_64_64_256:
                case AlgorithmValuesInt.AES_CCM_16_128_256:
                case AlgorithmValuesInt.AES_CCM_64_128_256:
                case AlgorithmValuesInt.AES_KW_256:
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384:
                    cbitKey = 384;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_512:
                    cbitKey = 512;
                    break;

                default:
                    throw new CoseException("NYI");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            CBORObject keyManagement = FindAttribute(HeaderKeys.Algorithm);
            if (keyManagement.Type == CBORType.Integer) {
                switch ((AlgorithmValuesInt) keyManagement.AsInt32()) {
                case AlgorithmValuesInt.DIRECT:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Key and key managment algorithm don't match");
                    byte[] rgb = m_key.AsBytes(CoseKeyParameterKeys.Octet_k);
                    if (rgb.Length * 8 != cbitKey) throw new CoseException("Incorrect key size");
                    return rgb;


                case AlgorithmValuesInt.Direct_HKDF_AES_128:
                case AlgorithmValuesInt.Direct_HKDF_AES_256:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF_AES(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg);

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha256Digest());

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha512Digest());

                case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                    {
                        if ((!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) && (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP))) throw new CoseException("Key and key management algorithm don't match");

                        ECDH_GenerateEphemeral();

                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);

                        return HKDF(rgbSecret, cbitKey, alg, new Sha256Digest());
                    }

                case AlgorithmValuesInt.ECDH_ES_HKDF_512: {
                        if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) throw new CoseException("Key and key management algorithm don't match");

                        ECDH_GenerateEphemeral();

                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);

                        return HKDF(rgbSecret, cbitKey, alg, new Sha512Digest());
                    }

                case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    {
                        if ((!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) &&
                            (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_OKP))) throw new CoseException("Key and key managment algorithm don't match");
                        if (FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce) == null) {
                            byte[] rgbAPU = new byte[512 / 8];
                            s_PRNG.NextBytes(rgbAPU);
                            AddAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce, CBORObject.FromObject(rgbAPU), UNPROTECTED);
                        }
                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);
                        return HKDF(rgbSecret, cbitKey, alg, new Sha256Digest());
                    }

                case AlgorithmValuesInt.ECDH_SS_HKDF_512: {
                        if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_EC)) throw new CoseException("Key and key managment algorithm don't match");
                        if (FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce) == null) {
                            byte[] rgbAPU = new byte[512 / 8];
                            s_PRNG.NextBytes(rgbAPU);
                            AddAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce, CBORObject.FromObject(rgbAPU), UNPROTECTED);
                        }
                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);
                        return HKDF(rgbSecret, cbitKey, alg, new Sha512Digest());
                    }

                default:
                    throw new CoseException("Unsupported algorithm");
                }
            }
            else if (keyManagement.Type == CBORType.TextString) {
                switch (keyManagement.AsString()) {
                case "dir+kdf": 
                    if (!m_key[CoseKeyKeys.KeyType].Equals(GeneralValues.KeyType_Octet)) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha256Digest());
                    
                default:
                    throw new CoseException("Unsupported algorithm");

                }
            }
         
            throw new CoseException("NYI");
        }

        public void SetKey(OneKey recipientKey)
        {
            m_key = recipientKey;
        }

        public void SetSenderKey(OneKey senderKey)
        {
            m_senderKey = senderKey;
        }

        private void AES_KeyWrap(int keySize, byte[] rgbKey = null)
        {
            if (rgbKey == null) {
                CBORObject cborKeyType = m_key[CoseKeyKeys.KeyType];
                if ((cborKeyType == null) || (cborKeyType.Type != CBORType.Integer) ||
                    (cborKeyType.AsInt32() != (int) GeneralValuesInt.KeyType_Octet)) throw new CoseException("Key is not correct type");

                rgbKey = m_key.AsBytes(CoseKeyParameterKeys.Octet_k);
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(true, parameters);
            RgbEncrypted = foo.Wrap(rgbContent, 0, rgbContent.Length);
        }

        private byte[] AES_KeyUnwrap(OneKey keyObject, int keySize, byte[] rgbKey=null)
        {
            if (keyObject != null) {
                CBORObject cborKeyType = m_key[CoseKeyKeys.KeyType];
                if ((cborKeyType == null) || (cborKeyType.Type != CBORType.Integer) ||
                    (cborKeyType.AsInt32() != (int) GeneralValuesInt.KeyType_Octet)) throw new CoseException("Key is not correct type");

                rgbKey = keyObject.AsBytes(CoseKeyParameterKeys.Octet_k);
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(false, parameters);
            rgbContent = foo.Unwrap(RgbEncrypted, 0, RgbEncrypted.Length);
            return rgbContent;
        }

        private void RSA_OAEP_KeyWrap(IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, m_key.AsBigInteger(CoseKeyParameterKeys.RSA_n), m_key.AsBigInteger(CoseKeyParameterKeys.RSA_e));

            cipher.Init(true, new ParametersWithRandom(pubParameters, s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            RgbEncrypted = outBytes;
        }

        private byte[] RSA_OAEP_KeyUnwrap(OneKey key, IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters priv;
            if (key.ContainsName(CoseKeyParameterKeys.RSA_dP)) {
                priv = new RsaPrivateCrtKeyParameters(key.AsBigInteger(CoseKeyParameterKeys.RSA_n), key.AsBigInteger(CoseKeyParameterKeys.RSA_e), key.AsBigInteger(CoseKeyParameterKeys.RSA_d),
                                                     key.AsBigInteger(CoseKeyParameterKeys.RSA_p), key.AsBigInteger(CoseKeyParameterKeys.RSA_q), key.AsBigInteger(CoseKeyParameterKeys.RSA_dP),
                                                     key.AsBigInteger(CoseKeyParameterKeys.RSA_dQ), key.AsBigInteger(CoseKeyParameterKeys.RSA_qInv));
            }
            else {
                priv = new RsaKeyParameters(true, key.AsBigInteger(CoseKeyParameterKeys.RSA_n), key.AsBigInteger(CoseKeyParameterKeys.RSA_d));
            }

            cipher.Init(false, new ParametersWithRandom(priv));

            byte[] outBytes = cipher.ProcessBlock(RgbEncrypted, 0, RgbEncrypted.Length);

            return outBytes;

        }

        private void AES_GCM_KeyWrap(byte[] rgbKeyIn, int keySize)
        {
            byte[] keyBytes;
            if (rgbKeyIn != null) {
                if (m_key != null) throw new CoseException("Can't supply an explicit key when wrapping.");
                keyBytes = rgbKeyIn;
            }
            else {
                if (m_key.AsString("kty") != "oct") throw new CoseException("Incorrect key type");
                keyBytes = m_key.AsBytes(CoseKeyParameterKeys.Octet_k);
                if (keyBytes.Length != keySize / 8) throw new CoseException("Key is not the correct size");
            }

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(keyBytes);
            byte[] A = new byte[0];
            byte[] IV = FindAttribute("iv").GetByteString();
            byte[] tag = FindAttribute("tag").GetByteString();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(RgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(RgbEncrypted, 0, RgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new CoseException("NYI");
            RgbEncrypted = C;
        }

        private byte[] AES_GCM_KeyUnwrap(OneKey key, int keySize)
        {
            if (key.AsString("kty") != "oct") return null;
            byte[] keyBytes = key.AsBytes(CoseKeyParameterKeys.Octet_k);
            if (keyBytes.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(keyBytes);
            byte[] A = new byte[0];
            byte[] IV = FindAttribute("iv").GetByteString();
            byte[] tag = FindAttribute("tag").GetByteString();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(RgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(RgbEncrypted, 0, RgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new CoseException("NYI");
            return C;

        }

        public static bool FUseCompressed = true;
        private void ECDH_GenerateEphemeral()
        {
            CBORObject epk = CBORObject.NewMap();
            epk.Add(CoseKeyKeys.KeyType, m_key[CoseKeyKeys.KeyType]);

            OneKey secretKey = new OneKey();

            switch (m_key.GetKeyType()) {
#if true
                case GeneralValuesInt.KeyType_OKP:
                epk.Add(CoseKeyParameterKeys.OKP_Curve, m_key[CoseKeyParameterKeys.OKP_Curve]);
                secretKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                switch ((GeneralValuesInt) epk[CoseKeyParameterKeys.OKP_Curve].AsInt32()) {
                case GeneralValuesInt.X25519: {
                    X25519KeyPairGenerator pGen = new X25519KeyPairGenerator();
                    X25519KeyGenerationParameters genParam = new X25519KeyGenerationParameters(s_PRNG);
                    pGen.Init(genParam);

                    AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();
                    X25519PublicKeyParameters pub = (X25519PublicKeyParameters) p1.Public;

                    epk.Add(CoseKeyParameterKeys.EC_X, pub.GetEncoded());

                    secretKey.Add(CoseKeyParameterKeys.OKP_Curve, m_key[CoseKeyParameterKeys.OKP_Curve]);
                    secretKey.Add(CoseKeyParameterKeys.OKP_D, CBORObject.FromObject(((X25519PrivateKeyParameters) p1.Private).GetEncoded()));
                    m_senderKey = secretKey;
                    break;
                }

                case GeneralValuesInt.X448: {
                    X448KeyPairGenerator pGen = new X448KeyPairGenerator();
                    X448KeyGenerationParameters genParam = new X448KeyGenerationParameters(s_PRNG);
                    pGen.Init(genParam);

                    AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();
                    X448PublicKeyParameters pub = (X448PublicKeyParameters) p1.Public;

                    epk.Add(CoseKeyParameterKeys.EC_X, pub.GetEncoded());

                    secretKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_OKP);
                    secretKey.Add(CoseKeyParameterKeys.OKP_Curve, m_key[CoseKeyParameterKeys.OKP_Curve]);
                    secretKey.Add(CoseKeyParameterKeys.OKP_D, CBORObject.FromObject(((X448PrivateKeyParameters)p1.Private).GetEncoded()));
                    m_senderKey = secretKey;
                    break;
                }
                }

                break;
#endif
                case GeneralValuesInt.KeyType_EC2: {
                    X9ECParameters p = m_key.GetCurve();
                    ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                    ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                    ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, s_PRNG);
                    pGen.Init(genParam);

                    AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                    ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;

                    epk.Add(CoseKeyParameterKeys.EC_Curve, m_key[CoseKeyParameterKeys.EC_Curve]);
                    if (FUseCompressed) {
                        byte[] rgbEncoded = priv.Q.Normalize().GetEncoded(true);
                        byte[] X = new byte[rgbEncoded.Length - 1];
                        Array.Copy(rgbEncoded, 1, X, 0, X.Length);
                        epk.Add(CoseKeyParameterKeys.EC_X, CBORObject.FromObject(X));
                        epk.Add(CoseKeyParameterKeys.EC_Y, CBORObject.FromObject((rgbEncoded[0] & 1) == 1));
                    }
                    else {
                        epk.Add(CoseKeyParameterKeys.EC_X,
                                PadBytes(priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned(),
                                         p.Curve.FieldSize));
                        epk.Add(CoseKeyParameterKeys.EC_Y,
                                PadBytes(priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned(),
                                         p.Curve.FieldSize));
                    }

                    secretKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_EC);
                    secretKey.Add(CoseKeyParameterKeys.EC_Curve, m_key[CoseKeyParameterKeys.EC_Curve]);
                    secretKey.Add(CoseKeyParameterKeys.EC_X, epk[CoseKeyParameterKeys.EC_X]);
                    secretKey.Add(CoseKeyParameterKeys.EC_Y, epk[CoseKeyParameterKeys.EC_Y]);
                    ECPrivateKeyParameters priv1 = (ECPrivateKeyParameters) p1.Private;
                    secretKey.Add(CoseKeyParameterKeys.EC_D, CBORObject.FromObject(priv1.D.ToByteArrayUnsigned()));
                    m_senderKey = secretKey;
                    break;
                }
                }

            AddAttribute(HeaderKeys.EphemeralKey, epk, UNPROTECTED);
        }

        private byte[] PadBytes(byte[] rgbIn, int outSize)
        {
            outSize = (outSize + 7) / 8;
            if (rgbIn.Length == outSize) return rgbIn;
            byte[] x = new byte[outSize];
            Array.Copy(rgbIn, 0, x, outSize - rgbIn.Length, rgbIn.Length);
            return x;
        }

        private byte[] ECDH_GenerateSecret(OneKey key)
        {
            OneKey epk;

            if (key[CoseKeyKeys.KeyType].Type != CBORType.Integer) throw new CoseException("Not an EC Key");

            if (m_senderKey != null) {
                epk = key;
                key = m_senderKey;
            }
            else {
                CBORObject spkT = FindAttribute(HeaderKeys.StaticKey);
                if (spkT != null) {
                    epk = new OneKey(spkT);
                }
                else {
                    CBORObject epkT = FindAttribute(HeaderKeys.EphemeralKey);
                    if (epkT == null) throw new CoseException("No Ephemeral key");
                    epk = new OneKey(epkT);
                }
            }

            switch ((GeneralValuesInt) key[CoseKeyKeys.KeyType].AsInt32()) {
#if true
                case GeneralValuesInt.KeyType_OKP:
                if (epk[CoseKeyParameterKeys.OKP_Curve].AsInt32() != key[CoseKeyParameterKeys.OKP_Curve].AsInt32()) throw new CoseException("Not a match of curves");

                switch ((GeneralValuesInt) epk[CoseKeyParameterKeys.OKP_Curve].AsInt32()) {
                case GeneralValuesInt.X25519: {
                    X25519PublicKeyParameters pub =
                        new X25519PublicKeyParameters(epk.AsBytes(CoseKeyParameterKeys.OKP_X), 0);
                    X25519PrivateKeyParameters priv =
                        new X25519PrivateKeyParameters(key.AsBytes(CoseKeyParameterKeys.OKP_D), 0);

                    X25519Agreement agree = new X25519Agreement();
                    agree.Init(priv);
                    byte[] secret = new byte[32];
                    agree.CalculateAgreement(pub, secret, 0);
#if FOR_EXAMPLES
                    m_secret = secret;
#endif
                    return secret;
                }

                case GeneralValuesInt.X448: {
                    X448PublicKeyParameters pub =
                        new X448PublicKeyParameters(epk.AsBytes(CoseKeyParameterKeys.OKP_X), 0);
                    X448PrivateKeyParameters priv =
                        new X448PrivateKeyParameters(key.AsBytes(CoseKeyParameterKeys.OKP_D), 0);

                    X25519Agreement agree = new X25519Agreement();
                    agree.Init(priv);
                    byte[] secret = new byte[agree.AgreementSize];
                    agree.CalculateAgreement(pub, secret, 0);
#if FOR_EXAMPLES
                    m_secret = secret;
#endif
                    return secret;

                }

                default:
                    throw new CoseException("Not a supported Curve");
                }
                break;
#endif

            case GeneralValuesInt.KeyType_EC2: {

                if (epk[CoseKeyParameterKeys.EC_Curve].AsInt32() != key[CoseKeyParameterKeys.EC_Curve].AsInt32())
                    throw new CoseException("not a match of curves");

                //  Get the curve

                X9ECParameters p = epk.GetCurve();
                ECPoint pubPoint = epk.GetPoint();

                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                ECPrivateKeyParameters priv =
                    new ECPrivateKeyParameters(key.AsBigInteger(CoseKeyParameterKeys.EC_D), parameters);

                IBasicAgreement e1 = new ECDHBasicAgreement();
                e1.Init(priv);

                BigInteger k1 = e1.CalculateAgreement(pub);

#if FOR_EXAMPLES
                m_secret = PadBytes(k1.ToByteArrayUnsigned(), p.Curve.FieldSize);
#endif

                return PadBytes(k1.ToByteArrayUnsigned(), p.Curve.FieldSize);
            }

            default:
                throw new CoseException("Not an EC Key");
            }
        }

        public byte[] GetKDFInput(int cbitKey, CBORObject algorithmID)
        {
            CBORObject obj;

            //  Build the context structure
            CBORObject contextArray = CBORObject.NewArray();

            //  First element is - algorithm ID
            contextArray.Add(algorithmID);

            //  Second element is - Party U info
            CBORObject info = CBORObject.NewArray();
            contextArray.Add(info);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_ID);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_Other);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);

            //  third element is - Party V info
            info = CBORObject.NewArray();
            contextArray.Add(info);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyV_ID);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyV_nonce);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyV_Other);
            if (obj != null) info.Add(obj);
            else info.Add(CBORObject.Null);

            //  fourth element is - Supplimental Public Info
            info = CBORObject.NewArray();
            contextArray.Add(info);
            info.Add(CBORObject.FromObject(cbitKey));
            if (ProtectedMap.Count == 0) info.Add(new byte[0]);
            else info.Add(ProtectedMap.EncodeToBytes());
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_SuppPub_Other);
            if (obj != null) info.Add(obj);

            //  Fifth element is - Supplimental Private Info
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_SuppPriv_Other);
            if (obj != null) contextArray.Add(obj);

#if FOR_EXAMPLES
            m_context = contextArray.EncodeToBytes();
#endif

            return contextArray.EncodeToBytes();
        }

        private byte[] HKDF(byte[] secret, int cbitKey, CBORObject algorithmID, IDigest digest)
        {
            CBORObject obj;

            byte[] rgbContext = GetKDFInput(cbitKey, algorithmID);

            //  See if we have salt
            obj = FindAttribute(CoseKeyParameterKeys.HKDF_Salt);

            //  Now start doing HKDF
            //  Perform the Extract phase
            HMac mac = new HMac(digest);

            int hashLength = digest.GetDigestSize();
            int c = ((cbitKey + 7)/8 + hashLength-1)/hashLength;

            byte[] K = new byte[digest.GetDigestSize()];
            if (obj != null) K = obj.GetByteString();
            KeyParameter key = new KeyParameter(K);
            mac.Init(key);
            mac.BlockUpdate(secret, 0, secret.Length);

            byte[] rgbExtract = new byte[hashLength];
            mac.DoFinal(rgbExtract, 0);


            //  Now do the Expand Phase

            byte[] rgbOut = new byte[cbitKey / 8];
            byte[] rgbT = new byte[hashLength * c];
            mac = new HMac(digest);
            key = new KeyParameter(rgbExtract);
            mac.Init(key);
            byte[] rgbLast = new byte[0];
            byte[] rgbHash2 = new byte[hashLength];

            for (int i = 0; i < c; i++) {
                mac.Reset();
                mac.BlockUpdate(rgbLast, 0, rgbLast.Length);
                mac.BlockUpdate(rgbContext, 0, rgbContext.Length);
                mac.Update((byte) (i + 1));

                rgbLast = rgbHash2;
                mac.DoFinal(rgbLast, 0);
                Array.Copy(rgbLast, 0, rgbT, i * hashLength, hashLength);
            }

            Array.Copy(rgbT, 0, rgbOut, 0, cbitKey / 8);
            return rgbOut;
        }

        private byte[] HKDF_AES(byte[] secret, int cbitKey, CBORObject algorithmID)
        {
            byte[] rgbContext = GetKDFInput(cbitKey, algorithmID);


            //  Setup for computing CBC-MAC
            IBlockCipher aes = new AesEngine();

            IMac mac;

            int hashLength = 128/8;
            int c = ((cbitKey + 7) / 8 + hashLength - 1) / hashLength;
            
            KeyParameter key = new KeyParameter(secret);

            //  Now do the Expand Phase

            byte[] rgbOut = new byte[cbitKey / 8];
            byte[] rgbT = new byte[hashLength * c];
            mac = new CbcBlockCipherMac(aes, 128, null);
            mac.Init(key);
            byte[] rgbLast = new byte[0];
            byte[] rgbHash2 = new byte[hashLength];

            for (int i = 0; i < c; i++) {
                mac.Reset();
                mac.BlockUpdate(rgbLast, 0, rgbLast.Length);
                mac.BlockUpdate(rgbContext, 0, rgbContext.Length);
                mac.Update((byte) (i + 1));

                rgbLast = rgbHash2;
                mac.DoFinal(rgbLast, 0);
                Array.Copy(rgbLast, 0, rgbT, i * hashLength, hashLength);
            }

            Array.Copy(rgbT, 0, rgbOut, 0, cbitKey / 8);
            return rgbOut;
        }

#if false
        private byte[] KDF(byte[] secret, int cbitKey, CBORObject algorithmID)
        {
#if USE_OLD_KDF
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
            Debug.Assert(algorithmID.Type == CBORType.TextString);
            byte[] algId = UTF8Encoding.ASCII.GetBytes(algorithmID.AsString());

            CBORObject j = FindAttribute("apu");
            if (j != null) rgbPartyU = j.GetByteString();

            j = FindAttribute("apv");
            if (j != null) rgbPartyV = j.GetByteString();

            int c = 4 + secret.Length + 4 + algId.Length + 4 + rgbPartyU.Length + 4 + rgbPartyV.Length + 4;
            byte[] rgb = new byte[c];

            //  Counter starts at 0

            Array.Copy(secret, 0, rgb, 4, secret.Length);
            c = 4 + secret.Length;

            if (algorithmID.Type == CBORType.TextString) {
                if (algorithmID.AsString().Length > 255) throw new CoseException("Internal error");
                rgb[c + 3] = (byte) algId.Length;
                Array.Copy(algId, 0, rgb, c + 4, algId.Length);
                c += 4 + algorithmID.AsString().Length;
            }
            else throw new CoseException("Unknown encoding for algorithm identifier in KDF function");

            if (rgbPartyU.Length > 255) throw new CoseException("Internal error");
            rgb[c + 3] = (byte) rgbPartyU.Length;
            Array.Copy(rgbPartyU, 0, rgb, c + 4, rgbPartyU.Length);
            c += 4 + rgbPartyU.Length;

            if (rgbPartyV.Length > 255) throw new CoseException("internal error");
            rgb[c + 3] = (byte) rgbPartyV.Length;
            Array.Copy(rgbPartyV, 0, rgb, c + 4, rgbPartyV.Length);
            c += 4 + rgbPartyV.Length;

            if (cbitKey / (256 * 256) != 0) throw new CoseException("internal error");
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
#else

            //  Do the KDF function
            byte[] rgbIter = new byte[4];

            CBORObject dataArray = CBORObject.NewArray();
            dataArray.Add(algorithmID);

            string PartyUInfo = null;
            if (UnprotectedMap.ContainsKey("PartyUInfo")) PartyUInfo = UnprotectedMap["PartyUInfo"].AsString();
            dataArray.Add(PartyUInfo);

            string PartyVInfo = null;
            if (UnprotectedMap.ContainsKey("PartyVInfo")) PartyVInfo = UnprotectedMap["PartyVInfo"].AsString();
            dataArray.Add(PartyVInfo);

            byte[] SubPubInfo = new byte[4];
            SubPubInfo[3] = (byte) cbitKey;
            dataArray.Add(SubPubInfo);

            dataArray.Add(null); // SubPrivInfo

            byte[] rgbData = dataArray.EncodeToBytes();
            Sha256Digest sha256 = new Sha256Digest();
            sha256.BlockUpdate(rgbIter, 0, rgbIter.Length);
            sha256.BlockUpdate(secret, 0, rgbIter.Length);
            sha256.BlockUpdate(rgbData, 0, rgbData.Length);
            byte[] rgbOut = new byte[sha256.GetByteLength()];
            sha256.DoFinal(rgbOut, 0);

            byte[] rgbResult = new byte[cbitKey / 8];
            Array.Copy(rgbOut, rgbResult, rgbResult.Length);

            return rgbResult;
#endif
        }
#endif

        public static byte[] PBKF2(byte[] password, byte[] salt, int iterCount, int cOctets, IDigest digest)
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
            ICipherParameters K = new KeyParameter(password);
            hmac.Init(K);
            int hLen = hmac.GetMacSize();
            int l = (cOctets + hLen - 1) / hLen;

            byte[] rgbStart = new byte[salt.Length + 4];
            Array.Copy(salt, rgbStart, salt.Length);
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
                    for (int k = 0; k < rgbH.Length; k++) rgbT[k] ^= rgbH[k];
                }

                Array.Copy(rgbT, hLen * (i - 1), rgbOutput, 0, rgbT.Length);
            }

            byte[] rgbOut = new Byte[cOctets];
            Array.Copy(rgbOutput, rgbOut, cOctets);
            return rgbOut;
        }

#if FOR_EXAMPLES
        byte[] m_kek = null;
        byte[] m_secret = null;
        byte[] m_context = null;

        public byte[] getKEK()
        {
            return m_kek;
        }

        public byte[] getSecret() { return m_secret; }
        public byte[] getContext() { return m_context; }
#endif // FOR_EXAMPLES
    }


    public class EncryptMessage : EncryptCommon
    {
        private readonly List<Recipient> _recipientList = new List<Recipient>();

        public EncryptMessage() : base(true, true, "Encrypt")
        {
            m_tag = Tags.Encrypt;
        }

        public EncryptMessage(Boolean emitTag, Boolean emitContent) : base(emitTag, emitContent, "Encrypt")
        {
            m_tag = Tags.Encrypt;
        }

        public List<Recipient> RecipientList
        {
            get => _recipientList;
        }

#region Decoders
        /// <summary>
        /// Given a byte array, decode and return the correct COSE message object.
        /// Message type can be provided explicitly or inferred from the CBOR tag element.
        /// If the explicit and inferred elements provide different answers, then it fails.
        /// </summary>
        /// <param name="messageData"></param>
        /// <param name="defaultTag"></param>
        /// <returns></returns>
        public static EncryptMessage DecodeFromBytes(byte[] messageData)
        {
            CBORObject messageObject = CBORObject.DecodeFromBytes(messageData);

            return (EncryptMessage)DecodeFromCBOR(messageObject, Tags.Encrypt);
        }

        public static EncryptMessage DecodeFromCBOR(CBORObject obj)
        {
            return (EncryptMessage)Message.DecodeFromCBOR(obj, Tags.Encrypt);
        }

        protected override void InternalDecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 4) throw new CoseException("Invalid Encrypt structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                ProtectedBytes = obj[0].GetByteString();
                if (obj[0].GetByteString().Length == 0) {
                    ProtectedMap = CBORObject.NewMap();
                }
                else {
                    ProtectedMap = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                }
                if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid Encrypt structure");
            }
            else {
                throw new CoseException("Invalid Encrypt structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid Encrypt structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) RgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encrypt structure");
            }

            // Recipients
            if (obj[3].Type == CBORType.Array) {
                // An array of recipients to be processed
                for (int i = 0; i < obj[3].Count; i++) {
                    Recipient recip = new Recipient();
                    recip.DecodeFromCBORObject(obj[3][i]);
                    _recipientList.Add(recip);
                }
            }
            else throw new CoseException("Invalid Encrypt structure");
        }
#endregion

        public override CBORObject Encode()
        {
            CBORObject obj;
            byte[] rgbProtect;

            if (RgbEncrypted == null) Encrypt();

            obj = CBORObject.NewArray();

            if (ProtectedMap.Count > 0) {
                rgbProtect = ProtectedMap.EncodeToBytes();
            }
            else {
                rgbProtect = new byte[0];
            }
            obj.Add(rgbProtect);

            ProcessCounterSignatures();

            obj.Add(UnprotectedMap); // Add unprotected attributes

            if (!m_emitContent) obj.Add(CBORObject.Null);
            else obj.Add(RgbEncrypted);      // Add ciphertext

            if ((_recipientList.Count == 1) && !m_forceArray) {
                CBORObject recipient = _recipientList[0].Encode();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (_recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in _recipientList) {
                    recipients.Add(key.Encode());
                }
                obj.Add(recipients);
            }
            else {
                // obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }

        public void AddRecipient(Recipient recipient)
        {
            recipient.SetContext("Env_Recipient");
            _recipientList.Add(recipient);
        }

        public virtual byte[] Decrypt(Recipient recipientIn)
        {
            //  Get the CEK
            byte[] CEK = null;
            int cbitCEK = 0;

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) throw new CoseException("No Algorithm Specified");

            cbitCEK = GetKeySize(alg);

            foreach (Recipient recipient in _recipientList) {
                try {
                    if (recipient == recipientIn) {
                        CEK = recipient.Decrypt(cbitCEK, alg);
                    }
                    else if (recipient.RecipientList.Count > 0) {
                        CEK = recipient.Decrypt(cbitCEK, alg, recipientIn);
                    }
                    else if (recipientIn == null) {
                        CEK = recipient.Decrypt(cbitCEK, alg);
                    }
                }
                catch (CoseException) { }
                if (CEK != null) break;
            }

            if (CEK == null) {
                throw new CoseException("No Recipient information found");
            }

            DecryptWithKey(CEK);

            return rgbContent;
        }

        virtual public void Encrypt()
        {
            CBORObject alg;

            //  Get the algorithm we are using - the default is AES GCM

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) throw new CoseException("No Algorithm Specified");

            /*
            if (alg == null) {
                alg = AlgorithmValues.AES_GCM_128;
                AddProtected(HeaderKeys.Algorithm, alg);
            }
            */

            byte[] ContentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            foreach (Recipient key in _recipientList) {
                switch (key.recipientType) {
                case RecipientType.direct:
                case RecipientType.keyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new CoseException("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    ContentKey = key.GetKey(alg);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new CoseException("It is not legal to mix direct and indirect recipients in a message");
            if (recipientTypes == 0) throw new CoseException("No recipients supplied");

            if (ContentKey == null) {
                ContentKey = new byte[GetKeySize(alg) / 8];
                s_PRNG.NextBytes(ContentKey);
            }
            EncryptWithKey(ContentKey);

            foreach (Recipient key in _recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }

            ProcessCounterSignatures();
        }
    }

}
