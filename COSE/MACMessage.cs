using System;
using System.Collections.Generic;

using PeterO.Cbor;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Macs;

using System.Diagnostics;

namespace Com.AugustCellars.COSE
{

    public class MAC0Message : MacMessageCommon
    {
        public MAC0Message(bool fEmitTag = true, bool fEmitContent = true) : base(fEmitTag, fEmitContent, "MAC0")
        {
            m_tag = Tags.MAC0;
        }

        public void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 4) throw new CoseException("Invalid MAC0 structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                byte[] data = obj[0].GetByteString();
                if (data.Length == 0) {
                    ProtectedMap = CBORObject.NewMap();
                }
                else {
                    ProtectedMap = CBORObject.DecodeFromBytes(data);
                    if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid MAC0 structure");
                }
            }
            else {
                throw new CoseException("Invalid MAC0 structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid MAC0 structure");

            // Plain Text
            if (obj[2].Type == CBORType.ByteString) rgbContent = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid MAC0 structure");
            }

            // Authentication tag
            if (obj[3].Type == CBORType.ByteString) RgbTag = obj[3].GetByteString();
            else throw new CoseException("Invalid MAC0 structure");
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            if (RgbTag == null) throw new CoseException("Must call Compute before encoding");

            obj = CBORObject.NewArray();

            if (ProtectedMap.Count > 0) obj.Add(ProtectedMap.EncodeToBytes());
            else obj.Add(new byte[0]);

            if (UnprotectedMap.Count > 0) obj.Add(UnprotectedMap); // Add unprotected attributes
            else obj.Add(CBORObject.NewMap());

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(RgbTag);

            return obj;
        }

        public void Compute(byte[] contentKey)
        {
            CBORObject alg;

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) {
                alg = AlgorithmValues.HMAC_SHA_256;
                if (UnprotectedMap == null) UnprotectedMap = CBORObject.NewMap();
                UnprotectedMap.Add(HeaderKeys.Algorithm, alg);

            }

            if (rgbContent == null) throw new CoseException("No Content Specified");

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-CMAC-128/64":
                case "AES-CMAC-256/64":
                    RgbTag = AES_CMAC(alg, contentKey);
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_384:
                case AlgorithmValuesInt.HMAC_SHA_512:
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                    RgbTag = HMAC(alg, contentKey);
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    RgbTag = AES_CBC_MAC(alg, contentKey);
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");
        }

        public bool Validate(OneKey recipientReceiver)
        {
            byte[] rgbKey;

            if (recipientReceiver[CoseKeyKeys.KeyType].AsInt32() != (int)GeneralValuesInt.KeyType_Octet) {
                throw new CoseException("Key type not octet");
            }
            rgbKey = recipientReceiver[CoseKeyParameterKeys.Octet_k].GetByteString();

            return Validate(rgbKey);
        }

        public bool Validate(byte[] rgbKey)
        { 
            int cbitKey;

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-CMAC-128/64":
                    cbitKey = 128;
                    break;

                case "AES-CMAC-256/64":
                    cbitKey = 256;
                    break;

                default:
                    throw new CoseException("Unknown Algoirthm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384: cbitKey = 384; break;
                case AlgorithmValuesInt.HMAC_SHA_512: cbitKey = 512; break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    cbitKey = 256;
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }

            }
            else throw new CoseException("Algorithm incorrectly encoded");

            if (rgbKey == null) throw new CoseException("No Key Provided");
            if (cbitKey / 8 != rgbKey.Length) throw new CoseException("Incorrect key length for operation");

            byte[] rgbCheck;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-CMAC-128/64":
                case "AES-CMAC-256/64":
                    rgbCheck = AES_CMAC(alg, rgbKey);
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_384:
                case AlgorithmValuesInt.HMAC_SHA_512:
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                    rgbCheck = HMAC(alg, rgbKey);
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    rgbCheck = AES_CBC_MAC(alg, rgbKey);
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            bool fReturn = true;
            for (int i = 0; i < rgbCheck.Length; i++) {
                fReturn &= (RgbTag[i] == rgbCheck[i]);
            }
            return fReturn;
        }
    }

    public class MACMessage : MacMessageCommon
    {

        public MACMessage(bool fEmitTag = true, bool fEmitContent = true) : base(fEmitTag, fEmitContent, "MAC")
        {
            m_tag = Tags.MAC;
        }

        private readonly List<Recipient> _recipientList = new List<Recipient>();
        public List<Recipient> RecipientList { get { return _recipientList; } }

        public virtual void AddRecipient(Recipient recipient)
        {
            if (recipient == null) throw new CoseException("Recipient is null");
            recipient.SetContext("Mac_Recipient");
            _recipientList.Add(recipient);
        }

        public void DecodeFromCBORObject(CBORObject obj)
        {

            if (obj.Count != 5) throw new CoseException("Invalid MAC structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                byte[] data = obj[0].GetByteString();
                if (data.Length > 0) {
                    ProtectedMap = CBORObject.DecodeFromBytes(data);
                    if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid MAC structure");
                }
                else ProtectedMap = CBORObject.NewMap();
            }
            else {
                throw new CoseException("Invalid MAC structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid MAC structure");

            // Plain Text
            if (obj[2].Type == CBORType.ByteString) rgbContent = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid MAC structure");
            }

            // Authentication tag
            if (obj[3].Type == CBORType.ByteString) RgbTag = obj[3].GetByteString();
            else throw new CoseException("Invalid MAC structure");


            // Recipients
            if (obj[4].Type == CBORType.Array) {
                // An array of recipients to be processed
                for (int i = 0; i < obj[4].Count; i++) {
                    Recipient recip = new Recipient();
                    recip.DecodeFromCBORObject(obj[4][i]);
                    _recipientList.Add(recip);
                }
            }
            else throw new CoseException("Invalid MAC structure");
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            if (RgbTag == null) MAC();

            obj = CBORObject.NewArray();

            if (ProtectedMap.Count > 0) obj.Add(ProtectedMap.EncodeToBytes());
            else obj.Add(new byte[0]);

            if (UnprotectedMap.Count > 0) obj.Add(UnprotectedMap); // Add unprotected attributes
            else obj.Add(CBORObject.NewMap());

            obj.Add(rgbContent);      // Add ciphertext
            obj.Add(RgbTag);

            if ((!m_forceArray) && (_recipientList.Count == 1)) {
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
                obj.Add(null);      // No recipients - set to null
            }

            return obj;
        }


public virtual void Compute()
        {
            MAC();
        } 

        public virtual void MAC()
        {
            CBORObject alg;
            int cbitKey;

            if (rgbContent == null) throw new CoseException("No Content Specified");

            //  Get the algorithm we are using - the default is AES GCM

            alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg == null) {
                alg = AlgorithmValues.HMAC_SHA_256;
                if (UnprotectedMap == null) UnprotectedMap = CBORObject.NewMap();
                UnprotectedMap.Add(HeaderKeys.Algorithm, alg);

            }
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
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
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384: cbitKey = 384; break;
                case AlgorithmValuesInt.HMAC_SHA_512: cbitKey = 512; break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    cbitKey = 256;
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            byte[] contentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            foreach (Recipient key in _recipientList) {
                switch (key.recipientType) {
                case RecipientType.direct:
                case RecipientType.keyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new CoseException("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    contentKey = key.GetKey(alg);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new CoseException("It is not legal to mix direct and indirect recipients in a message");
            if (recipientTypes == 0) throw new CoseException("No recipients supplied");

            if (contentKey == null) {
                contentKey = new byte[cbitKey / 8];
                s_PRNG.NextBytes(contentKey);
            }

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-CMAC-128/64":
                case "AES-CMAC-256/64":
                    RgbTag = AES_CMAC(alg, contentKey);
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_384:
                case AlgorithmValuesInt.HMAC_SHA_512:
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                    RgbTag = HMAC(alg, contentKey);
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    RgbTag = AES_CBC_MAC(alg, contentKey);
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");


            foreach (Recipient key in _recipientList) {
                key.SetContent(contentKey);
                key.Encrypt();
            }

#if FOR_EXAMPLES
            m_cek = contentKey;
#endif
        }

        public bool Validate(Recipient recipientReceiver)
        {
            byte[] rgbKey = null;
            int cbitKey;

            CBORObject alg = FindAttribute(HeaderKeys.Algorithm);
            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
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
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384: cbitKey = 384; break;
                case AlgorithmValuesInt.HMAC_SHA_512: cbitKey = 512; break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    cbitKey = 256;
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");


            foreach (Recipient msgRecpient in _recipientList) {
                if (recipientReceiver == msgRecpient) {
                    try {
                        rgbKey = msgRecpient.Decrypt(cbitKey, alg);
                    }
                    catch (CoseException) { }
                }
                else if (recipientReceiver.RecipientList.Count > 0) {
                    try {
                        rgbKey = recipientReceiver.Decrypt(cbitKey, alg, recipientReceiver);
                    }
                    catch (CoseException) {
                    }
                }
                if (rgbKey != null) break;
            }

            if (rgbKey == null) throw new CoseException("Recipient not found");

            byte[] rgbCheck;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                case "AES-CMAC-128/64":
                case "AES-CMAC-256/64":
                    rgbCheck = AES_CMAC(alg, rgbKey);
                    break;

                default:
                    throw new CoseException("Unknown Algorithm Specified");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                case AlgorithmValuesInt.HMAC_SHA_384:
                case AlgorithmValuesInt.HMAC_SHA_512:
                case AlgorithmValuesInt.HMAC_SHA_256_64:
                    rgbCheck = HMAC(alg, rgbKey);
                    break;

                case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                    rgbCheck = AES_CBC_MAC(alg, rgbKey);
                    break;

                default:
                    throw new CoseException("MAC algorithm not recognized " + alg.AsInt32());
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            bool fReturn = true;
            for (int i = 0; i < rgbCheck.Length; i++) {
                fReturn &= (RgbTag[i] == rgbCheck[i]);
            }
            return fReturn;
        }


#if FOR_EXAMPLES
        byte[] m_cek = null;
        public byte[] getCEK() { return m_cek; }
#endif
    }

    public abstract class MacMessageCommon : Message
    {
        private readonly string _strContext;

        protected MacMessageCommon(bool fEmitTag, bool fEmitContent, string context) : base(fEmitTag, fEmitContent)
        {
            _strContext = context;
        }

        protected byte[] RgbTag { get; set; }

#if FOR_EXAMPLES
        public byte[] BuildContentBytes()
#else
        private byte[] BuildContentBytes()
#endif
        {
            CBORObject obj = CBORObject.NewArray();

            obj.Add(_strContext);
            if (ProtectedBytes == null) {
                if (ProtectedMap.Count > 0) ProtectedBytes = ProtectedMap.EncodeToBytes();
                else ProtectedBytes = new byte[0];
            }
            obj.Add(ProtectedBytes);
            if (ExternalData != null) obj.Add(CBORObject.FromObject(ExternalData));
            else obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(rgbContent);

            return obj.EncodeToBytes();
        }

        protected byte[] AES_CBC_MAC(CBORObject alg, byte[] K)
        {
            int cbitKey;
            int cbitTag;
            //  Defaults to PKCS#7

            IBlockCipher aes = new AesEngine();

            KeyParameter ContentKey;

            //  The requirements from spec
            //  IV is 128 bits of zeros
            //  key sizes are 128, 192 and 256 bits
            //  Authentication tag sizes are 64 and 128 bits

            Debug.Assert(alg.Type == CBORType.Number);
            switch ((AlgorithmValuesInt) alg.AsInt32()) {
            case AlgorithmValuesInt.AES_CBC_MAC_128_64:
                cbitKey = 128;
                cbitTag = 64;
                break;

            case AlgorithmValuesInt.AES_CBC_MAC_256_64:
                cbitKey = 256;
                cbitTag = 64;
                break;

            case AlgorithmValuesInt.AES_CBC_MAC_128_128:
                cbitKey = 128;
                cbitTag = 128;
                break;

            case AlgorithmValuesInt.AES_CBC_MAC_256_128:
                cbitKey = 256;
                cbitTag = 128;
                break;

            default:
                throw new CoseException("Unrecognized algorithm");
            }

            IMac mac = new CbcBlockCipherMac(aes, cbitTag, null);

            if (K.Length != cbitKey / 8) throw new CoseException("Key is incorrectly sized");
            ContentKey = new KeyParameter(K);

            //  Build the text to be digested

            mac.Init(ContentKey);

            byte[] toDigest = BuildContentBytes();

            byte[] C = new byte[128 / 8];
            mac.BlockUpdate(toDigest, 0, toDigest.Length);
            mac.DoFinal(C, 0);

            byte[] rgbResult = new byte[cbitTag / 8];
            Array.Copy(C, 0, rgbResult, 0, cbitTag / 8);

            return rgbResult;
        }

        protected byte[] AES_CMAC(CBORObject alg, byte[] K)
        {
            int cbitKey;
            int cbitTag;

            IBlockCipher aes = new AesEngine();
            CMac mac = new CMac(aes);

            KeyParameter ContentKey;

            //  The requirements from spec
            //  IV is 128 bits of zeros
            //  key sizes are 128, 192 and 256 bits
            //  Authentication tag sizes are 64 and 128 bits

            Debug.Assert(alg.Type == CBORType.TextString);
            switch (alg.AsString()) {
            case "AES-CMAC-128/64":
                cbitKey = 128;
                cbitTag = 64;
                break;

            case "AES-CMAC-256/64":
                cbitKey = 256;
                cbitTag = 64;
                break;

            default:
                throw new CoseException("Unrecognized algorithm");
            }

            if (K.Length != cbitKey / 8) throw new CoseException("Key is incorrectly sized");

            ContentKey = new KeyParameter(K);

            //  Build the text to be digested

            mac.Init(ContentKey);

            byte[] toDigest = BuildContentBytes();

            byte[] C = new byte[128 / 8];
            mac.BlockUpdate(toDigest, 0, toDigest.Length);
            mac.DoFinal(C, 0);

            byte[] rgbOut = new byte[cbitTag / 8];
            Array.Copy(C, 0, rgbOut, 0, cbitTag / 8);

            return rgbOut;
        }

        protected byte[] HMAC(CBORObject alg, byte[] K)
        {
            int cbResult;
            IDigest digest;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {
                default:
                    throw new CoseException("Unrecognized algorithm");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbResult = 256 / 8;
                    digest = new Sha256Digest();
                    break;

                case AlgorithmValuesInt.HMAC_SHA_256_64:
                    digest = new Sha256Digest();
                    cbResult = 64 / 8;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_384:
                    digest = new Sha384Digest();
                    cbResult = 384 / 8;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_512:
                    digest = new Sha512Digest();
                    cbResult = 512 / 8;
                    break;

                default:
                    throw new CoseException("Unknown or unsupported algorithm");
                }
            }
            else throw new CoseException("Algorithm incorrectly encoded");

            if (K == null) throw new CoseException("No Key value");

            HMac hmac = new HMac(digest);
            KeyParameter key = new KeyParameter(K);
            byte[] resBuf = new byte[hmac.GetMacSize()];

            byte[] toDigest = BuildContentBytes();

            hmac.Init(key);
            hmac.BlockUpdate(toDigest, 0, toDigest.Length);
            hmac.DoFinal(resBuf, 0);

            byte[] rgbOut = new byte[cbResult];
            Array.Copy(resBuf, rgbOut, cbResult);

            return rgbOut;
        }
    }
}
