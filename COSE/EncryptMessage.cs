using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.Nist;
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
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

using System.Diagnostics;

namespace COSE
{
    public abstract class EncryptCommon : Message
    {
        protected CBORObject obj;
        protected string context;

        protected byte[] rgbEncrypted;
        protected byte[] rgbContent;
        byte[] m_cek;

        public EncryptCommon(Boolean fEmitTag, Boolean fEmitContent) : base(fEmitTag, fEmitContent) { }

        protected void DecryptWithKey(byte[] CEK)
        {
            if (rgbEncrypted == null) throw new CoseException("No Encrypted Content supplied");
            if (CEK == null) throw new CoseException("Null Key Supplied");

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) throw new CoseException("No Algorithm Specified");

            if (alg.Type == CBORType.TextString) {
                throw new CoseException("Algorithm not supported " + alg.AsString());
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_GCM_256:
                    AES_Decrypt(alg, CEK);
                    break;

                case AlgorithmValuesInt.AES_CCM_16_64_128:
                case AlgorithmValuesInt.AES_CCM_16_64_256:
                case AlgorithmValuesInt.AES_CCM_16_128_128:
                case AlgorithmValuesInt.AES_CCM_16_128_256:
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                case AlgorithmValuesInt.AES_CCM_64_64_256:
                case AlgorithmValuesInt.AES_CCM_64_128_128:
                case AlgorithmValuesInt.AES_CCM_64_128_256:
                    AES_CCM_Decrypt(alg, CEK);
                    break;

                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    ChaCha20_Poly1305_Decrypt(alg, CEK);
                    break;

                default:
                    throw new CoseException("Unknown algorithm found");
                }

            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        public void EncryptWithKey(byte[] ContentKey)
        {
            CBORObject alg;

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) throw new CoseException("No Algorithm Specified");

            if (ContentKey == null) throw new CoseException("Null Key Provided");
            if (GetKeySize(alg) / 8 != ContentKey.Length) throw new CoseException("Incorrect Key Size");

            if (rgbContent == null) throw new CoseException("No Content Specified");
    
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "A128CBC-HS256":
                case "A192CBC-HS256":
                case "A256CBC-HS256":
                    throw new CoseException("Content encryption algorithm is not supported");

                default:
                    throw new CoseException("Content encryption algorithm is not recognized");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_GCM_256:
                    ContentKey = AES(alg, ContentKey);
                    break;

                case AlgorithmValuesInt.AES_CCM_16_64_128:
                case AlgorithmValuesInt.AES_CCM_16_64_256:
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                case AlgorithmValuesInt.AES_CCM_64_64_256:
                case AlgorithmValuesInt.AES_CCM_16_128_128:
                case AlgorithmValuesInt.AES_CCM_16_128_256:
                case AlgorithmValuesInt.AES_CCM_64_128_128:
                case AlgorithmValuesInt.AES_CCM_64_128_256:
                    ContentKey = AES_CCM(alg, ContentKey);
                    break;

                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    ContentKey = ChaCha20_Poly1305(alg, ContentKey);
                    break;

                default:
                    throw new CoseException("Content encryption algorithm is not recognized");
                }
            }

#if FOR_EXAMPLES
            m_cek = ContentKey;
#endif // FOR_EXAMPLES

            return;
        }

        #if FOR_EXAMPLES
        public byte[] getCEK()
        {
            return this.m_cek;
        }
#endif

        public byte[] GetContent()
        {
            return rgbContent;
        }

        public string GetContentAsString()
        {
            return UTF8Encoding.ASCII.GetString(rgbContent);
        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.ASCII.GetBytes(contentString);
        }

        public byte[] GetEncryptedContent()
        {
            return rgbEncrypted;
        }

        public void SetEncryptedContent(byte[] rgb)
        {
            rgbEncrypted = rgb;
        }

        public void SetContext(string newContext)
        {
            context = newContext;
        }

        public int GetKeySize(CBORObject alg)
        {
            if (alg.Type == CBORType.TextString) {
                throw new CoseException("Unrecognized Algorithm Specified");
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_CCM_16_64_128:
                case AlgorithmValuesInt.AES_CCM_16_128_128:
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                case AlgorithmValuesInt.AES_CCM_64_128_128:
                    return 128;

                case AlgorithmValuesInt.AES_GCM_192:
                    return 192;

                case AlgorithmValuesInt.AES_GCM_256:
                case AlgorithmValuesInt.AES_CCM_16_64_256:
                case AlgorithmValuesInt.AES_CCM_16_128_256:
                case AlgorithmValuesInt.AES_CCM_64_64_256:
                case AlgorithmValuesInt.AES_CCM_64_128_256:
                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    return 256;

                default:
                    throw new CoseException("Unrecognized Algorithm Specified");
                }

            }
            throw new CoseException("Invalid Algorithm Specified");
        }

        private byte[] AES(CBORObject alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;
            byte[] IV;
            CBORObject cbor;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96 / 8];
            cbor = FindAttribute(HeaderKeys.IV);
            if (cbor != null) {
                if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorreclty formed.");
                if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, IV.Length - cbor.GetByteString().Length, cbor.GetByteString().Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
            }

            if (K == null) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                    K = new byte[128 / 8];
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                    K = new byte[192 / 8];
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                    K = new byte[256 / 8];
                    break;

                default:
                    throw new CoseException("Unsupported algorithm: " + alg);
                }
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed
            
            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, getAADBytes());

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbEncrypted = C;

            return K;
        }

        public void AES_Decrypt(CBORObject alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            ContentKey = new KeyParameter(K);

            byte[] IV = new byte[96 / 8];
            CBORObject cbor = FindAttribute(HeaderKeys.IV);
            if (cbor == null) throw new Exception("Missing IV");

                if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorrectly formed.");
                if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, IV.Length - cbor.GetByteString().Length, cbor.GetByteString().Length);

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, getAADBytes());

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;

        }

        private byte[] AES_CCM(CBORObject alg, byte[] K)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesFastEngine());
            KeyParameter ContentKey;
            int cbitTag = 64;
            int cbIV;
            int cbitKey;

            //  Figure out what the correct internal parameters to use are

            Debug.Assert(alg.Type == CBORType.Number);
            switch ((AlgorithmValuesInt) alg.AsInt32()) {
            case AlgorithmValuesInt.AES_CCM_16_64_128:
            case AlgorithmValuesInt.AES_CCM_64_64_128:
                cbitKey = 128;
                cbitTag = 64;

                break;

            case AlgorithmValuesInt.AES_CCM_16_128_128:
            case AlgorithmValuesInt.AES_CCM_64_128_128:
                cbitKey = 128;
                cbitTag = 128;

                break;

            case AlgorithmValuesInt.AES_CCM_16_64_256:
            case AlgorithmValuesInt.AES_CCM_64_64_256:
                cbitKey = 256;
                cbitTag = 64;
                break;

            case AlgorithmValuesInt.AES_CCM_16_128_256:
            case AlgorithmValuesInt.AES_CCM_64_128_256:
                cbitKey = 256;
                cbitTag = 128;
                break;

            default:
                throw new CoseException("Unsupported algorithm: " + alg);
            }

            switch ((AlgorithmValuesInt) alg.AsInt32()) {
            case AlgorithmValuesInt.AES_CCM_16_64_128:
            case AlgorithmValuesInt.AES_CCM_16_64_256:
            case AlgorithmValuesInt.AES_CCM_16_128_128:
            case AlgorithmValuesInt.AES_CCM_16_128_256:
                cbIV = 15 - 2;
                break;

            case AlgorithmValuesInt.AES_CCM_64_64_128:
            case AlgorithmValuesInt.AES_CCM_64_64_256:
            case AlgorithmValuesInt.AES_CCM_64_128_256:
            case AlgorithmValuesInt.AES_CCM_64_128_128:
                cbIV = 15 - 8;
                break;

            default:
                throw new CoseException("Unsupported algorithm: " + alg);
            }

            //  The requirements from JWA

            byte[] IV = new byte[cbIV];
            CBORObject cbor = FindAttribute(HeaderKeys.IV);
            if (cbor != null) {
                if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorreclty formed.");
                if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, 0, IV.Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
            }

            if (K == null) {
                    K = new byte[cbitKey/8];
                s_PRNG.NextBytes(K);
            }

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            AeadParameters parameters = new AeadParameters(ContentKey, cbitTag, IV, getAADBytes());

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbEncrypted = C;

            return K;
        }

        private void AES_CCM_Decrypt(CBORObject alg, byte[] K)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesFastEngine());
            KeyParameter ContentKey;
            int cbitTag = 64;
            int cbIV;
            int cbitKey;

            //  Figure out what the correct internal parameters to use are

            Debug.Assert(alg.Type == CBORType.Number);
            switch ((AlgorithmValuesInt) alg.AsInt32()) {
            case AlgorithmValuesInt.AES_CCM_16_64_128:
            case AlgorithmValuesInt.AES_CCM_64_64_128:
                cbitKey = 128;
                cbitTag = 64;
                break;

            case AlgorithmValuesInt.AES_CCM_16_128_128:
            case AlgorithmValuesInt.AES_CCM_64_128_128:
                cbitKey = 128;
                cbitTag = 128;
                break;

            case AlgorithmValuesInt.AES_CCM_16_64_256:
            case AlgorithmValuesInt.AES_CCM_64_64_256:
                cbitKey = 256;
                cbitTag = 64;
                break;

            case AlgorithmValuesInt.AES_CCM_16_128_256:
            case AlgorithmValuesInt.AES_CCM_64_128_256:
                cbitKey = 256;
                cbitTag = 128;
                break;

            default:
                throw new CoseException("Unsupported algorithm: " + alg);
            }

            switch ((AlgorithmValuesInt) alg.AsInt32()) {
            case AlgorithmValuesInt.AES_CCM_16_64_128:
            case AlgorithmValuesInt.AES_CCM_16_64_256:
            case AlgorithmValuesInt.AES_CCM_16_128_128:
            case AlgorithmValuesInt.AES_CCM_16_128_256:
                cbIV = 15 - 2;
                break;

            case AlgorithmValuesInt.AES_CCM_64_64_128:
            case AlgorithmValuesInt.AES_CCM_64_64_256:
            case AlgorithmValuesInt.AES_CCM_64_128_256:
            case AlgorithmValuesInt.AES_CCM_64_128_128:
                cbIV = 15 - 8;
                break;

            default:
                throw new CoseException("Unsupported algorithm: " + alg);
            }

            //  The requirements from JWA

            byte[] IV = new byte[cbIV];
            CBORObject cbor = FindAttribute(HeaderKeys.IV);
            if (cbor != null) {
                if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorrectly formed.");
                if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, 0, IV.Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
            }

            if (K == null) throw new CoseException("Internal error");
            if (K.Length != cbitKey / 8) throw new CoseException("Incorrect key length");

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            AeadParameters parameters = new AeadParameters(ContentKey, cbitTag, IV, getAADBytes());

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;
        }

        private byte[] ChaCha20_Poly1305(CBORObject alg, byte[] K)
        {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();

            KeyParameter ContentKey;
            int cbitTag = 128;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key size is 256 bits

            byte[] IV = new byte[96 / 8];
            CBORObject cbor = FindAttribute(HeaderKeys.IV);
            if (cbor != null) {
                if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorrectly formed.");
                if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, IV.Length - cbor.GetByteString().Length, cbor.GetByteString().Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddUnprotected(HeaderKeys.IV, CBORObject.FromObject(IV));
            }

            if (K == null) {
                Debug.Assert(alg.Type == CBORType.Number);
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    K = new byte[256 / 8];
                    cbitTag = 128;
                    break;

                default:
                    throw new CoseException("Unsupported algorithm: " + alg);
                }
                s_PRNG.NextBytes(K);
            }

            //  Generate key

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            byte[] aad = getAADBytes();
            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, aad);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbEncrypted = C;

            return K;

        }

        public void ChaCha20_Poly1305_Decrypt(CBORObject alg, byte[] K)
        {
            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            ContentKey = new KeyParameter(K);

            byte[] IV = new byte[96 / 8];
            CBORObject cbor = FindAttribute(HeaderKeys.IV);
            if (cbor == null) throw new Exception("Missing IV");

            if (cbor.Type != CBORType.ByteString) throw new CoseException("IV is incorrectly formed.");
            if (cbor.GetByteString().Length > IV.Length) throw new CoseException("IV is too long.");
            Array.Copy(cbor.GetByteString(), 0, IV, IV.Length - cbor.GetByteString().Length, cbor.GetByteString().Length);

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, getAADBytes());

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;

        }

#if FOR_EXAMPLES
        public byte[] getAADBytes()
        {
            CBORObject obj = CBORObject.NewArray();

            obj.Add(context);
            if (objProtected.Count == 0) obj.Add(CBORObject.FromObject(new byte[0]));
            else obj.Add( objProtected.EncodeToBytes());
            obj.Add(CBORObject.FromObject(externalData));

            return obj.EncodeToBytes();
        }

#endif // FOR_EXAMPLES
    }

    public enum RecipientType
    {
        direct=1, keyAgree=2, keyTransport=3, keyWrap=4, keyAgreeDirect=5, keyTransportAndWrap=6, password=7
    }

    public class Recipient : EncryptCommon
    {
        RecipientType m_recipientType;
        Key m_key;
        Key m_senderKey;
        List<Recipient> recipientList = new List<Recipient>();

        public Recipient(Key key, CBORObject algorithm = null) : base(true, true)
        {
            if (algorithm != null) {
                if (algorithm.Type == CBORType.TextString) {
                    switch (algorithm.AsString()) {
                    case "dir":  // Direct encryption mode
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Invalid parameters");
                        m_recipientType = RecipientType.direct;
                        break;

                    case "A128GCMKW":
                    case "A192GCMKW":
                    case "A256GCMKW":
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyWrap;
                        break;


                    case "PBES2-HS256+A128KW":
                    case "PBES2-HS256+A192KW":
                    case "PBES-HS256+A256KW":
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.password;
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else if (algorithm.Type == CBORType.Number) {
                    switch ((AlgorithmValuesInt) algorithm.AsInt32()) {
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    case AlgorithmValuesInt.Direct_HKDF_AES_128:
                    case AlgorithmValuesInt.Direct_HKDF_AES_256:
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Invalid parameters");
                    m_recipientType = RecipientType.direct;
                    break;


                    case AlgorithmValuesInt.RSA_OAEP:
                    case AlgorithmValuesInt.RSA_OAEP_256:
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_RSA) throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyTransport;
                        break;

                    case AlgorithmValuesInt.AES_KW_128:
                    case AlgorithmValuesInt.AES_KW_192:
                    case AlgorithmValuesInt.AES_KW_256:
                        if ((key != null) && (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet)) throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyWrap;
                        break;

                    case AlgorithmValuesInt.DIRECT:  // Direct encryption mode
                        if (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Invalid parameters");
                        m_recipientType = RecipientType.direct;
                        break;

                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_128:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_192:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_256_AES_KW_256:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_128:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_192:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256_AES_KW_256:
                        if ((key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) && (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_OKP)) throw new CoseException("Invalid Parameter");
                        m_recipientType = RecipientType.keyAgree;
                        break;

                    case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                    case AlgorithmValuesInt.ECDH_ES_HKDF_512:
#if DEBUG
                    case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    case AlgorithmValuesInt.ECDH_SS_HKDF_512:
#endif // DEBUG
                        if ((key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) && (key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_OKP)) throw new CoseException("Invalid Parameters");
                        m_recipientType = RecipientType.keyAgreeDirect;
                        break;

                    default:
                        throw new CoseException("Unrecognized recipient algorithm");
                    }
                }
                else throw new CoseException("Algorithm incorrectly encoded");

                m_key = key;
                AddUnprotected(HeaderKeys.Algorithm, algorithm);
            }
            else {
                if (key[CoseKeyKeys.KeyType].Type == CBORType.Number) {
                    switch ((GeneralValuesInt) key[CoseKeyKeys.KeyType].AsInt32()) {
                    case GeneralValuesInt.KeyType_Octet:
                        m_recipientType = RecipientType.keyWrap;
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
                        m_recipientType = RecipientType.keyTransport;
                        algorithm = AlgorithmValues.RSA_OAEP_256;
                        break;

                    case GeneralValuesInt.KeyType_EC2:
                        m_recipientType = RecipientType.keyAgree;
                        algorithm =  AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128;
                        break;
                    }
                    AddUnprotected(HeaderKeys.Algorithm, algorithm);
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

                if (key[CoseKeyKeys.KeyIdentifier] != null) AddUnprotected(HeaderKeys.KeyId, key[CoseKeyKeys.KeyIdentifier]);

                SetContext("Rec_Recipient");
            }
        }

        public Recipient() : base(true, true)
        {
        }

        public List<Recipient> RecipientList
        {
            get { return recipientList; }
        }

        public RecipientType recipientType { get { return m_recipientType; } }

        public void AddRecipient(Recipient recipient)
        {
            recipient.SetContext("Enc_Recipient");
            recipientList.Add(recipient);
        }

        public void DecodeFromCBORObject(CBORObject obj)
        {
            if ((obj.Count != 3) && (obj.Count != 4)) throw new CoseException("Invalid Encryption structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                if (obj[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else objProtected = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encryption Structure");
            }
            else {
                throw new CoseException("Invalid Encryption structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) objUnprotected = obj[1];
            else throw new CoseException("Invalid Encryption Structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) rgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encryption Structure");
            }

            // Recipients
            if (obj.Count == 4) {
                if (obj[3].Type == CBORType.Array) {
                    // An array of recipients to be processed
                    for (int i = 0; i < obj[3].Count; i++) {
                        Recipient recip = new Recipient();
                        recip.DecodeFromCBORObject(obj[3][i]);
                        recipientList.Add(recip);
                    }
                }
                else throw new CoseException("Invalid Encryption Structure");
            }
        }

        public byte[] Decrypt(int cbitCEK, CBORObject algCEK)
        {
            return Decrypt(m_key, cbitCEK, algCEK);
        }

        public byte[] Decrypt(Key key, int cbitCEK, CBORObject algCEK)
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
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.DIRECT:
                    if (key[CoseKeyKeys.KeyType].AsInt32() != (int) GeneralValuesInt.KeyType_Octet) return null;
                    return key.AsBytes(CoseKeyParameterKeys.Octet_k);

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK, new Sha256Digest());

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK, new Sha512Digest());

                case AlgorithmValuesInt.Direct_HKDF_AES_128:
                case AlgorithmValuesInt.Direct_HKDF_AES_256:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF_AES(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitCEK, algCEK);

                case AlgorithmValuesInt.RSA_OAEP: return RSA_OAEP_KeyUnwrap(key, new Sha1Digest());
                case AlgorithmValuesInt.RSA_OAEP_256: return RSA_OAEP_KeyUnwrap(key, new Sha256Digest());

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

            if (rgbEncrypted == null) Encrypt();

            if (m_counterSignerList.Count() != 0) {
                byte[] rgbProtected;
                if (objProtected.Count > 0) rgbProtected = objProtected.EncodeToBytes();
                else rgbProtected = new byte[0];
                if (m_counterSignerList.Count() == 1) {
                    AddUnprotected(HeaderKeys.CounterSignature, m_counterSignerList[0].EncodeToCBORObject(rgbProtected, rgbEncrypted));
                }
                else {
                    foreach (CounterSignature sig in m_counterSignerList) {
                        sig.EncodeToCBORObject(rgbProtected, rgbEncrypted);
                    }
                }
            }

            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(CBORObject.FromObject(new byte[0]));

            obj.Add(objUnprotected); // Add unprotected attributes

            if (rgbEncrypted == null) obj.Add(new byte[0]);
            else obj.Add(rgbEncrypted);      // Add ciphertext

            if ((recipientList.Count == 1) && !m_forceArray) {
                CBORObject recipient = recipientList[0].Encode();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in recipientList) {
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

            if (recipientList.Count> 0) {
                if (m_key != null) throw new CoseException("Can't mix nested recipients and fixed keys.");

                //  Determine if we are doing a direct encryption
                int recipientTypes = 0;

                foreach (Recipient key in recipientList) {
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
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
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
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
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
                        AddUnprotected("p2s", objSalt);
                    }
                    objIterCount = FindAttribute("p2c");
                    if (objIterCount == null) {
                        objIterCount = CBORObject.FromObject(8000);
                        AddUnprotected("p2c", objIterCount);
                    }
                    rgbKey = PBKF2(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), objSalt.GetByteString(), objIterCount.AsInt32(), 256 / 8, new Sha256Digest());
                    AES_KeyWrap(256, rgbKey);
                    break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else if (alg.Type == CBORType.Number) {
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

                case AlgorithmValuesInt.AES_KW_128: AES_KeyWrap(128, rgbKey); break;
                case AlgorithmValuesInt.AES_KW_192: AES_KeyWrap(192, rgbKey); break;
                case AlgorithmValuesInt.AES_KW_256: AES_KeyWrap(256, rgbKey); break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm: " + alg);
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            foreach (Recipient key in recipientList) {
                key.SetContent(rgbKey);
                key.Encrypt();
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
                    throw new CoseException("NYI");
                }
            }
            else if (alg.Type == CBORType.Number) {
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
            if (keyManagement.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) keyManagement.AsInt32()) {
                case AlgorithmValuesInt.DIRECT:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Key and key managment algorithm don't match");
                    byte[] rgb = m_key.AsBytes(CoseKeyParameterKeys.Octet_k);
                    if (rgb.Length * 8 != cbitKey) throw new CoseException("Incorrect key size");
                    return rgb;


                case AlgorithmValuesInt.Direct_HKDF_AES_128:
                case AlgorithmValuesInt.Direct_HKDF_AES_256:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF_AES(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg);

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_256:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha256Digest());

                case AlgorithmValuesInt.Direct_HKDF_HMAC_SHA_512:
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha512Digest());

                case AlgorithmValuesInt.ECDH_ES_HKDF_256:
                    {
                        if ((m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) && (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_OKP)) throw new CoseException("Key and key management algorithm don't match");

                        ECDH_GenerateEphemeral();

                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);

                        return HKDF(rgbSecret, cbitKey, alg, new Sha256Digest());
                    }

                case AlgorithmValuesInt.ECDH_ES_HKDF_512: {
                        if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) throw new CoseException("Key and key management algorithm don't match");

                        ECDH_GenerateEphemeral();

                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);

                        return HKDF(rgbSecret, cbitKey, alg, new Sha512Digest());
                    }

                case AlgorithmValuesInt.ECDH_SS_HKDF_256:
                    {
                        if ((m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) &&
                            (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_OKP)) throw new CoseException("Key and key managment algorithm don't match");
                        if (FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce) == null) {
                            byte[] rgbAPU = new byte[512 / 8];
                            s_PRNG.NextBytes(rgbAPU);
                            AddUnprotected(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce, CBORObject.FromObject(rgbAPU));
                        }
                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);
                        return HKDF(rgbSecret, cbitKey, alg, new Sha256Digest());
                    }

                case AlgorithmValuesInt.ECDH_SS_HKDF_512: {
                        if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_EC) throw new CoseException("Key and key managment algorithm don't match");
                        if (FindAttribute(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce) == null) {
                            byte[] rgbAPU = new byte[512 / 8];
                            s_PRNG.NextBytes(rgbAPU);
                            AddUnprotected(CoseKeyParameterKeys.HKDF_Context_PartyU_nonce, CBORObject.FromObject(rgbAPU));
                        }
                        byte[] rgbSecret = ECDH_GenerateSecret(m_key);
                        return HKDF(rgbSecret, cbitKey, alg, new Sha512Digest());
                    }

                default:
                    throw new CoseException("Unknown algorithm");
                }
            }
            else if (keyManagement.Type == CBORType.TextString) {
                switch (keyManagement.AsString()) {
                case "dir+kdf": 
                    if (m_key[CoseKeyKeys.KeyType] != GeneralValues.KeyType_Octet) throw new CoseException("Needs to be an octet key");
                    return HKDF(m_key.AsBytes(CoseKeyParameterKeys.Octet_k), cbitKey, alg, new Sha256Digest());
                    
                default:
                    throw new CoseException("Unknown algorithm");

                }
            }
         
            throw new CoseException("NYI");
        }

        public void SetKey(COSE.Key recipientKey)
        {
            m_key = recipientKey;
        }

        public void SetSenderKey(COSE.Key senderKey)
        {
            m_senderKey = senderKey;
        }

        private void AES_KeyWrap(int keySize, byte[] rgbKey = null)
        {
            if (rgbKey == null) {
                CBORObject cborKeyType = m_key[CoseKeyKeys.KeyType];
                if ((cborKeyType == null) || (cborKeyType.Type != CBORType.Number) ||
                    (cborKeyType.AsInt32() != (int) GeneralValuesInt.KeyType_Octet)) throw new CoseException("Key is not correct type");

                rgbKey = m_key.AsBytes(CoseKeyParameterKeys.Octet_k);
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(true, parameters);
            rgbEncrypted = foo.Wrap(rgbContent, 0, rgbContent.Length);
        }

        private byte[] AES_KeyUnwrap(Key keyObject, int keySize, byte[] rgbKey=null)
        {
            if (keyObject != null) {
                CBORObject cborKeyType = m_key[CoseKeyKeys.KeyType];
                if ((cborKeyType == null) || (cborKeyType.Type != CBORType.Number) ||
                    (cborKeyType.AsInt32() != (int) GeneralValuesInt.KeyType_Octet)) throw new CoseException("Key is not correct type");

                rgbKey = keyObject.AsBytes(CoseKeyParameterKeys.Octet_k);
            }
            if (rgbKey.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(false, parameters);
            rgbContent = foo.Unwrap(rgbEncrypted, 0, rgbEncrypted.Length);
            return rgbContent;
        }

        private void RSA_OAEP_KeyWrap(IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, m_key.AsBigInteger(CoseKeyParameterKeys.RSA_n), m_key.AsBigInteger(CoseKeyParameterKeys.RSA_e));

            cipher.Init(true, new ParametersWithRandom(pubParameters, s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            rgbEncrypted = outBytes;
        }

        private byte[] RSA_OAEP_KeyUnwrap(Key key, IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, key.AsBigInteger(CoseKeyParameterKeys.RSA_n), key.AsBigInteger(CoseKeyParameterKeys.RSA_e));

            cipher.Init(true, new ParametersWithRandom(pubParameters));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

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

            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
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
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new CoseException("NYI");
            rgbEncrypted = C;
            return;

        }

        private byte[] AES_GCM_KeyUnwrap(Key key, int keySize)
        {
            if (key.AsString("kty") != "oct") return null;
            byte[] keyBytes = key.AsBytes(CoseKeyParameterKeys.Octet_k);
            if (keyBytes.Length != keySize / 8) throw new CoseException("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
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
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
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

            switch (m_key.GetKeyType()) {
            case GeneralValuesInt.KeyType_OKP:
                epk.Add(CoseKeyParameterKeys.OKP_Curve, m_key[CoseKeyParameterKeys.OKP_Curve]);
                switch ((GeneralValuesInt) epk[CoseKeyParameterKeys.OKP_Curve].AsInt32()) {
                case GeneralValuesInt.X25519:
                    X25519KeyPair keyPair = X25519.GenerateKeyPair();
                    epk.Add(CoseKeyParameterKeys.OKP_X, keyPair.Public);
                    epk.Add(CoseKeyParameterKeys.OKP_D, keyPair.Private);
                    break;
                }
                break;

            case GeneralValuesInt.KeyType_EC2:
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
                    epk.Add(CoseKeyParameterKeys.EC_X, PadBytes(priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned(), p.Curve.FieldSize));
                    epk.Add(CoseKeyParameterKeys.EC_Y, PadBytes(priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned(), p.Curve.FieldSize));
                }
                break;
            }

            AddUnprotected(HeaderKeys.EphemeralKey, epk);
        }

        private byte[] PadBytes(byte[] rgbIn, int outSize)
        {
            outSize = (outSize + 7) / 8;
            if (rgbIn.Length == outSize) return rgbIn;
            byte[] x = new byte[outSize];
            Array.Copy(rgbIn, 0, x, outSize - rgbIn.Length, rgbIn.Length);
            return x;
        }

        private byte[] ECDH_GenerateSecret(Key key)
        {
            Key epk;

            if (key[CoseKeyKeys.KeyType].Type != CBORType.Number) throw new CoseException("Not an EC Key");

            if (m_senderKey != null) {
                epk = m_senderKey;
            }
            else {
                CBORObject spkT = FindAttribute(HeaderKeys.StaticKey);
                if (spkT != null) {
                    epk = new Key(spkT);
                }
                else {
                    CBORObject epkT = FindAttribute(HeaderKeys.EphemeralKey);
                    if (epkT == null) throw new CoseException("No Ephemeral key");
                    epk = new Key(epkT);
                }
            }

            byte[] temp;

            switch ((GeneralValuesInt) key[CoseKeyKeys.KeyType].AsInt32()) {
            case GeneralValuesInt.KeyType_OKP:
                if (epk[CoseKeyParameterKeys.OKP_Curve].AsInt32() != key[CoseKeyParameterKeys.OKP_Curve].AsInt32()) throw new CoseException("Not a match of curves");

                switch ((GeneralValuesInt) epk[CoseKeyParameterKeys.OKP_Curve].AsInt32()) {
                case GeneralValuesInt.X25519:
                    temp = X25519.CalculateAgreement(key.AsBytes(CoseKeyParameterKeys.OKP_X), epk.AsBytes(CoseKeyParameterKeys.OKP_D));
                    break;

                default:
                    throw new CoseException("Not a supported Curve");
                }
#if FOR_EXAMPLES
                m_secret = temp;
#endif
                return temp;

            case GeneralValuesInt.KeyType_EC2:

                if (epk[CoseKeyParameterKeys.EC_Curve].AsInt32() != key[CoseKeyParameterKeys.EC_Curve].AsInt32()) throw new CoseException("not a match of curves");

                //  Get the curve

                X9ECParameters p = key.GetCurve();
                ECPoint pubPoint = epk.GetPoint();

                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECPublicKeyParameters pub = new ECPublicKeyParameters(pubPoint, parameters);

                ECPrivateKeyParameters priv = new ECPrivateKeyParameters(key.AsBigInteger(CoseKeyParameterKeys.EC_D), parameters);

                IBasicAgreement e1 = new ECDHBasicAgreement();
                e1.Init(priv);

                BigInteger k1 = e1.CalculateAgreement(pub);

#if FOR_EXAMPLES
                m_secret = PadBytes(k1.ToByteArrayUnsigned(), p.Curve.FieldSize);
#endif

                return PadBytes(k1.ToByteArrayUnsigned(), p.Curve.FieldSize);

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
            if (objProtected.Count == 0) info.Add(new byte[0]);
            else info.Add(objProtected.EncodeToBytes());
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
            IBlockCipher aes = new AesFastEngine();
            byte[] IV = new byte[128 / 8];

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
            if (objUnprotected.ContainsKey("PartyUInfo")) PartyUInfo = objUnprotected["PartyUInfo"].AsString();
            dataArray.Add(PartyUInfo);

            string PartyVInfo = null;
            if (objUnprotected.ContainsKey("PartyVInfo")) PartyVInfo = objUnprotected["PartyVInfo"].AsString();
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
        public EncryptMessage() : base(true, true)
        {
            context = "Encrypt1";
            m_tag = Tags.Encrypted;
        }

        public EncryptMessage(bool fEmitTag, bool fEmitContent) :base(fEmitTag, fEmitContent)
        {
            context = "Encrypted";
            m_tag = Tags.Encrypted;
        }

        virtual public void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 3) throw new CoseException("Invalid Encryption structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                if (obj[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else objProtected = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encryption Structure");
            }
            else {
                throw new CoseException("Invalid Encryption structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) objUnprotected = obj[1];
            else throw new CoseException("Invalid Encryption Structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) rgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encryption Structure");
            }
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            if (rgbEncrypted == null) throw new CoseException("Must call Encrypt first");

            if (m_counterSignerList.Count() != 0) {
                CBORObject objX;
                if (objProtected.Count > 0) objX = CBORObject.FromObject(objProtected.EncodeToBytes());
                else objX = CBORObject.FromObject(new byte[0]);
                if (m_counterSignerList.Count() == 1) {
                    AddUnprotected(HeaderKeys.CounterSignature, m_counterSignerList[0].EncodeToCBORObject(rgbProtected, rgbEncrypted));
                }
                else {
                    foreach (CounterSignature sig in m_counterSignerList) {
                        sig.EncodeToCBORObject(rgbProtected, rgbEncrypted);
                    }
                }
            }
            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(CBORObject.FromObject(new byte[0]));

            obj.Add(objUnprotected); // Add unprotected attributes

            if (m_emitContent) obj.Add(rgbEncrypted);      // Add ciphertext
            else obj.Add(CBORObject.Null);

            return obj;
        }

        public byte[] Decrypt(byte[] rgbKey)
        {
            DecryptWithKey(rgbKey);
            return rgbContent;
        }

        public void Encrypt(byte[] rgbKey)
        {
            EncryptWithKey(rgbKey);
        }
    }

    public class EnvelopedMessage : EncryptCommon
    {
        protected List<Recipient> recipientList = new List<Recipient>();

#if FOR_EXAMPLES
        byte[] m_cek;
#endif // FOR_EXAMPLES

        public EnvelopedMessage() : base(true, true)
        {
            context = "Encrypt";
            m_tag = Tags.Enveloped;
        }

        public EnvelopedMessage(Boolean emitTag, Boolean emitContent) : base(emitTag, emitContent)
        {
            context = "Enveloped";
            m_tag = Tags.Enveloped;
        }

        public List<Recipient> RecipientList
        {
            get { return recipientList; }
        }

        virtual public void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 4) throw new CoseException("Invalid Encryption structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                if (obj[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else objProtected = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encryption Structure");
            }
            else {
                throw new CoseException("Invalid Encryption structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) objUnprotected = obj[1];
            else throw new CoseException("Invalid Encryption Structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) rgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encryption Structure");
            }

            // Recipients
            if (obj[3].Type == CBORType.Array) {
                // An array of recipients to be processed
                for (int i = 0; i < obj[3].Count; i++) {
                    Recipient recip = new Recipient();
                    recip.DecodeFromCBORObject(obj[3][i]);
                    recipientList.Add(recip);
                }
            }
            else throw new CoseException("Invalid Encryption Structure");
        }

        public override CBORObject Encode()
        {
            CBORObject obj;
            byte[] rgbProtect;

            if (rgbEncrypted == null) Encrypt();

            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                rgbProtect = objProtected.EncodeToBytes();
            }
            else {
                rgbProtect = new byte[0];
            }
            obj.Add(rgbProtect);

            if (m_counterSignerList.Count() != 0) {
                if (m_counterSignerList.Count() == 1) {
                    AddUnprotected(HeaderKeys.CounterSignature, m_counterSignerList[0].EncodeToCBORObject(rgbProtect, rgbEncrypted));
                }
                else {
                    foreach (CounterSignature sig in m_counterSignerList) {
                        sig.EncodeToCBORObject(rgbProtect, rgbEncrypted);
                    }
                }
            }


            obj.Add(objUnprotected); // Add unprotected attributes

            if (!m_emitContent) obj.Add(CBORObject.Null);
            else obj.Add(rgbEncrypted);      // Add ciphertext

            if ((recipientList.Count == 1) && !m_forceArray) {
                CBORObject recipient = recipientList[0].Encode();

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (recipientList.Count > 0) {
                CBORObject recipients = CBORObject.NewArray();

                foreach (Recipient key in recipientList) {
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
            recipientList.Add(recipient);
        }

        public virtual void Decrypt(Recipient recipientIn)
        {
            //  Get the CEK
            byte[] CEK = null;
            int cbitCEK = 0;

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) throw new CoseException("No Algorithm Specified");

            cbitCEK = GetKeySize(alg);

            foreach (Recipient recipient in recipientList) {
                try {
                    if (recipient == recipientIn) {
                        CEK = recipient.Decrypt(cbitCEK, alg);
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

            foreach (Recipient key in recipientList) {
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
            if (recipientTypes == 0) throw new CoseException("No Recipients Specified");

            if (ContentKey == null) {
                ContentKey = new byte[GetKeySize(alg) / 8];
                s_PRNG.NextBytes(ContentKey);
            }
            EncryptWithKey(ContentKey);

            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt();
            }
        }
    }

}
