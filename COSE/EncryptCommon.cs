using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;

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


namespace Com.AugustCellars.COSE
{
    public abstract class EncryptCommon : Message
    {
        private string _context;

#if FOR_EXAMPLES
        private byte[] _cek;
#endif

        protected EncryptCommon(Boolean fEmitTag, Boolean fEmitContent, string context) : base(fEmitTag, fEmitContent)
        {
            _context = context;
        }

        protected byte[] RgbEncrypted { get; set; }

        protected void DecryptWithKey(byte[] CEK)
        {
            if (RgbEncrypted == null)
                throw new CoseException("No Encrypted Content Specified.");
            if (CEK == null)
                throw new CoseException("Null Key Supplied");

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null)
                throw new CoseException("No Algorithm Specified");

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

#if CHACHA20
                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    ChaCha20_Poly1305_Decrypt(alg, CEK);
                    break;
#endif

                    default:
                        throw new CoseException("Unknown algorithm found");
                }

            }
            else
                throw new CoseException("Algorithm incorrectly encoded");
        }

        public void EncryptWithKey(byte[] contentKey)
        {
            CBORObject alg;

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null)
                throw new CoseException("No Algorithm Specified");

            if (contentKey == null)
                throw new CoseException("Null Key Provided");
            if (GetKeySize(alg) / 8 != contentKey.Length)
                throw new CoseException("Incorrect Key Size");

            if (rgbContent == null)
                throw new CoseException("No Content Specified");

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
                        contentKey = AES(alg, contentKey);
                        break;

                    case AlgorithmValuesInt.AES_CCM_16_64_128:
                    case AlgorithmValuesInt.AES_CCM_16_64_256:
                    case AlgorithmValuesInt.AES_CCM_64_64_128:
                    case AlgorithmValuesInt.AES_CCM_64_64_256:
                    case AlgorithmValuesInt.AES_CCM_16_128_128:
                    case AlgorithmValuesInt.AES_CCM_16_128_256:
                    case AlgorithmValuesInt.AES_CCM_64_128_128:
                    case AlgorithmValuesInt.AES_CCM_64_128_256:
                        contentKey = AES_CCM(alg, contentKey);
                        break;

#if CHACHA20
                case AlgorithmValuesInt.ChaCha20_Poly1305:
                    contentKey = ChaCha20_Poly1305(alg, contentKey);
                    break;
#endif

                    default:
                        throw new CoseException("Content encryption algorithm is not recognized");
                }
            }

#if FOR_EXAMPLES
            _cek = ContentKey;
#endif // FOR_EXAMPLES
        }

#if FOR_EXAMPLES
        public byte[] getCEK()
        {
            return _cek;
        }
#endif



        public byte[] GetEncryptedContent()
        {
            return RgbEncrypted;
        }

        public void SetEncryptedContent(byte[] rgb)
        {
            RgbEncrypted = rgb;
        }

        public void SetContext(string newContext)
        {
            _context = newContext;
        }

        public int GetKeySize(CBORObject alg)
        {
            if (alg.Type == CBORType.TextString) {
                throw new CoseException("Unknown Algorithm Specified");
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
                        throw new CoseException("Unknown Algorithm Specified");
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
                if (cbor.Type != CBORType.ByteString)
                    throw new CoseException("IV is incorrectly formed.");
                if (cbor.GetByteString().Length != IV.Length)
                    throw new CoseException("IV size is incorrect.");
                Array.Copy(cbor.GetByteString(), IV, IV.Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddAttribute(HeaderKeys.IV, CBORObject.FromObject(IV), UNPROTECTED);
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

            RgbEncrypted = C;

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
            if (cbor == null)
                throw new Exception("Missing IV");

            if (cbor.Type != CBORType.ByteString)
                throw new CoseException("IV is incorrectly formed.");
            if (cbor.GetByteString().Length > IV.Length)
                throw new CoseException("IV is too long.");
            Array.Copy(cbor.GetByteString(), 0, IV, IV.Length - cbor.GetByteString().Length, cbor.GetByteString().Length);

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, getAADBytes());

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(RgbEncrypted.Length)];
            int len = cipher.ProcessBytes(RgbEncrypted, 0, RgbEncrypted.Length, C, 0);
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
                if (cbor.Type != CBORType.ByteString)
                    throw new CoseException("IV is incorreclty formed.");
                if (cbor.GetByteString().Length > IV.Length)
                    throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, 0, IV.Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddAttribute(HeaderKeys.IV, CBORObject.FromObject(IV), UNPROTECTED);
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

            RgbEncrypted = C;

            return K;
        }

        private void AES_CCM_Decrypt(CBORObject alg, byte[] K)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesFastEngine());
            KeyParameter ContentKey;
            int cbitTag;
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
                if (cbor.Type != CBORType.ByteString)
                    throw new CoseException("IV is incorrectly formed.");
                if (cbor.GetByteString().Length > IV.Length)
                    throw new CoseException("IV is too long.");
                Array.Copy(cbor.GetByteString(), 0, IV, 0, IV.Length);
            }
            else {
                s_PRNG.NextBytes(IV);
                AddAttribute(HeaderKeys.IV, CBORObject.FromObject(IV), UNPROTECTED);
            }

            if (K == null)
                throw new CoseException("Internal error");
            if (K.Length != cbitKey / 8)
                throw new CoseException("Incorrect key length");

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            AeadParameters parameters = new AeadParameters(ContentKey, cbitTag, IV, getAADBytes());

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(RgbEncrypted.Length)];
            int len = cipher.ProcessBytes(RgbEncrypted, 0, RgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;
        }

#if CHACHA20
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
                AddAttribute(HeaderKeys.IV, CBORObject.FromObject(IV), UNPROTECTED);
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
            AeadParameters parameters = new AeadParameters(ContentKey, cbitTag, IV, aad);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            _rgbEncrypted = C;

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
            byte[] C = new byte[cipher.GetOutputSize(_rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(_rgbEncrypted, 0, _rgbEncrypted.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbContent = C;

        }
#endif

        public byte[] getAADBytes()
        {
            CBORObject obj = CBORObject.NewArray();

            obj.Add(_context);
            if (ProtectedMap.Count == 0)
                obj.Add(CBORObject.FromObject(new byte[0]));
            else
                obj.Add(ProtectedMap.EncodeToBytes());
            obj.Add(CBORObject.FromObject(ExternalData));

            // Console.WriteLine("COSE AAD = " + BitConverter.ToString(obj.EncodeToBytes()));

            return obj.EncodeToBytes();
        }
    }
}
