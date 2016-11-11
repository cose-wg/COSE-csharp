using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.IO.Compression;

using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;


namespace JOSE
{
    public class EncryptMessage : Message
    {
        byte[] IV;
        List<Recipient> recipientList = new List<Recipient>();
        protected byte[] rgbEncrypted;
        protected byte[] rgbContent;
        protected byte[] tag;
        protected byte[] aad;
        string strProtected;

        public EncryptMessage()
        {
        }

        public void AddRecipient(Recipient recipient)
        {
            recipientList.Add(recipient);
        }

        new public void DecodeFromJSON(JSON json)
        {
            if (json.ContainsKey("protected")) {
                strProtected = json["protected"].AsString();
                objProtected = JSON.Parse(UTF8Encoding.UTF8.GetString(base64urldecode(strProtected)));
            }

            if (json.ContainsKey("unprotected")) {
                objUnprotected = json["unprotected"];
            }

            if (json.ContainsKey("iv")) {
                IV = base64urldecode(json["iv"].AsString());
            }

            if (json.ContainsKey("aad")) { 
                    aad = base64urldecode(json["aad"].AsString());
                    aad = UTF8Encoding.UTF8.GetBytes(json["aad"].AsString());
            }

            rgbEncrypted = base64urldecode(json["ciphertext"].AsString());

            if (json.ContainsKey("tag")) {
                tag = base64urldecode(json["tag"].AsString());
            }

            if (json.ContainsKey("recipients")) {
                JSON recips = json["recipients"];
                for (int i=0; i<recips.Count; i++) {
                    Recipient recipient = new Recipient();
                    recipient.DecodeFromJSON(recips[i]);
                    recipientList.Add(recipient);
                }
            }
            else {
                Recipient recipient = new Recipient();
                recipient.DecodeFromJSON(json);
                recipientList.Add(recipient);
            }
        }
     
        public void Decrypt(Key key)
        {
            //  Get the CEK
            byte[] CEK = null;
            int cbitCEK = 0;

            string alg = FindAttribute("enc").AsString();
            switch (alg) {
            case "A128GCM":
                cbitCEK = 128;
                break;

            case "A192GCM":
                cbitCEK = 192;
                break;

            case "A256GCM":
            case "A128CBC-HS256":
                cbitCEK = 256;
                break;

            case "A192CBC-HS256":
                cbitCEK = 384;
                break;

            case "A256CBC-HS256":
                cbitCEK = 512;
                break;

            }

            foreach (Recipient recipient in recipientList) {
                try {
                    CEK = recipient.Decrypt(key, cbitCEK, this);
                    if (CEK != null) break;
                }
                catch (Exception e) { }
            }

            if (CEK == null) {
                //  Generate a null CEK
                throw new JOSE_Exception("Failed to get a CEK");
            }


            switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                AES_GCM_Decrypt(alg, CEK);
                break;

            case "A128CBC-HS256":
            case "A192CBC-HS256":
            case "A256CBC-HS256":
                AES_CBC_MAC_Decrypt(alg, CEK);
                break;
            }

            //  Check for compression now

            if (FindAttribute("zip") != null) {
                MemoryStream stm = new MemoryStream(rgbContent);
                DeflateStream zipStm = new DeflateStream(stm, CompressionMode.Decompress);
                MemoryStream stm2 = new MemoryStream();
                zipStm.CopyTo(stm2);

                rgbContent = stm2.GetBuffer();
            }
        }

        public string Encode()
        {
            JSON obj3;

            obj3 = EncodeToJSON();

            return obj3.ToString();
        }

        public string EncodeCompact()
        {
            JSON obj3;
            JSON objRecip = null;
            string str = "";

            if (recipientList.Count() != 1) throw new JOSE_Exception("Compact encoding cannot have more than one recipient");
            ForceArray(true);
            obj3 = EncodeToJSON();

            if (obj3.ContainsKey("recipients")) objRecip = obj3["recipients"][0];
            if (obj3.ContainsKey("aad")) throw new JOSE_Exception("Compact encoding cannot have additional authenticated data");
            if (objRecip != null && objRecip.ContainsKey("header")) throw new JOSE_Exception("Compact encoding cannot have recipient header data");

            if (obj3.ContainsKey("protected")) str += obj3["protected"].AsString();
            str += ".";
            if (obj3.ContainsKey("unprotected")) throw new JOSE_Exception("Compact encoding cannot have unprotected attributes");

            if (objRecip != null && objRecip.ContainsKey("encrypted_key")) str += objRecip["encrypted_key"].AsString();
            str += ".";
            if (obj3.ContainsKey("iv")) str += obj3["iv"].AsString();
            str += ".";
            if (obj3.ContainsKey("ciphertext")) str += obj3["ciphertext"].AsString();
            str += ".";
            if (obj3.ContainsKey("tag")) str += obj3["tag"].AsString();

            return str;
        }

        public JSON EncodeToJSON()
        {
            JSON obj = new JSON();

            if (rgbEncrypted == null) Encrypt();

            if (objProtected.Count > 0) {
                obj.Add("protected", base64urlencode(UTF8Encoding.UTF8.GetBytes( objProtected.ToString())));
            }

            if (objUnprotected.Count > 0) obj.Add("unprotected", objUnprotected); // Add unprotected attributes

            if (IV != null) obj.Add("iv", base64urlencode( IV ));      // Add iv

            if (aad != null) obj.Add("aad", UTF8Encoding.UTF8.GetString(aad));

            if (rgbEncrypted != null) obj.Add("ciphertext", base64urlencode(rgbEncrypted));      // Add ciphertext
            obj.Add("tag", base64urlencode(tag));

            if ((recipientList.Count == 1) && !forceAsArray) {
                JSON recipient = recipientList[0].EncodeToJSON();

                if ((recipient != null) && (recipient.Count != 0)) {
                    foreach (KeyValuePair<string, JSON> pair in recipient.map) {
                        obj.Add(pair.Key, pair.Value);
                    }
                }
            }
            else if (recipientList.Count > 0) {
                JSON recipients = new JSON();

                foreach (Recipient key in recipientList) {
                    JSON j = key.EncodeToJSON();
                    if ((j != null) && (j.Count != 0)) recipients.Add(j);
                }
                if (recipients.Count > 0)  obj.Add("recipients", recipients);
            }
            return obj;
        }

        public virtual void Encrypt()
        {
            string alg;

            //  Get the algorithm we are using - the default is AES GCM

            try {
                alg = FindAttribute("enc").AsString();
            }
            catch {
                alg = "A128GCM";
                AddUnprotected("enc", "A128GCM");
            }


            byte[] ContentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            foreach (Recipient key in recipientList) {
                switch (key.recipientType) {
                case RecipientType.direct:
                case RecipientType.keyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new JOSE_Exception("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    ContentKey = key.GetKey(alg, this);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new JOSE_Exception("It is not legal to mix direct and indirect recipients in a message");

            if (ContentKey == null) {
                switch (alg) {
                case "A128GCM":
                case "AES-128-CCM-64":
                    ContentKey = new byte[128 / 8];
                    break;

                case "AES192GCM":
                    ContentKey = new byte[192 / 8];
                    break;

                case "AES256GCM":
                    ContentKey = new byte[256 / 8];
                    break;

                case "A128CBC-HS256":
                    ContentKey = new byte[2*128 / 8];
                    break;

                case "A192CBC-HS256":
                    ContentKey = new byte[2*192 / 8];
                    break;

                case "A256CBC-HS256":
                    ContentKey = new byte[2*256 / 8];
                    break;

                default:
                    throw new JOSE_Exception("Internal Error");

                }

                s_PRNG.NextBytes(ContentKey);
            }

            foreach (Recipient key in recipientList) {
                key.SetContent(ContentKey);
                key.Encrypt(this);
            }

            //  Encode the protected attributes if there are any

            if (objProtected.Count > 0) {
                strProtected = base64urlencode(UTF8Encoding.UTF8.GetBytes(objProtected.ToString()));
            }

            switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                ContentKey = AES_GCM_Encrypt(alg, ContentKey);
                break;

            case "AES-128-CCM-64":
                ContentKey = AES_CCM(alg, ContentKey);
                break;

            case "A128CBC-HS256":
            case "A192CBC-HS256":
            case "A256CBC-HS256":
                ContentKey = AES_CBC_MAC_Encrypt(alg, ContentKey);
                break;

            default:
                throw new JOSE_Exception("Content encryption algorithm is not recognized");
            }



            return;
        }

        public string GetContentAsString()
        {
            return UTF8Encoding.UTF8.GetString(rgbContent);
        }

        public void SetAAD(byte[] data)
        {
            aad = UTF8Encoding.UTF8.GetBytes( base64urlencode(data));
        }

        public void SetAAD(string text)
        {
            SetAAD( UTF8Encoding.UTF8.GetBytes(text));
        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetContent(string contentString)
        {
            rgbContent = UTF8Encoding.UTF8.GetBytes(contentString);
        }

        private byte[] CreateAAD()
        {
            int cb = 0;

            if (strProtected != null) {
                cb = strProtected.Length;
            }
            if (aad != null) {
                cb += aad.Length + 1;
            }

            byte[] rgbOut = new byte[cb];
            cb = 0;

            if (strProtected != null) {
                byte[] rgbX = UTF8Encoding.UTF8.GetBytes(strProtected);
                Array.Copy(rgbX, rgbOut, rgbX.Length);
                cb = rgbX.Length;
            }

            if (aad != null) {
                rgbOut[cb] = 0x2e;
                Array.Copy(aad, 0, rgbOut, cb+1, aad.Length);
            }

            return rgbOut;
        }

        private byte[] AES_GCM_Encrypt(string alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96 / 8];
            s_PRNG.NextBytes(IV);

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            byte[] A = CreateAAD();
            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            rgbEncrypted = C;
            tag = cipher.GetMac();
            Array.Resize(ref rgbEncrypted, rgbEncrypted.Length - tag.Length);

            return K;
        }

        private void AES_GCM_Decrypt(string alg, byte[] K)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            ContentKey = new KeyParameter(K);

            byte[] A = CreateAAD();

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            rgbContent = C;

        }

        private byte[] AES_CBC_MAC_Encrypt(string alg, byte[] K)
        {
            KeyParameter key;

            int t_len;

            switch (alg) {
            case "A128CBC-HS256":
                t_len = 16;
                break;

            case "A192CBC-HS256":
                t_len = 24;
                break;

            case "A256CBC-HS256":
                t_len = 32;
                break;

            default:
                throw new JOSE_Exception("Internal error");
            }

            IV = new byte[128 / 8];
            s_PRNG.NextBytes(IV);

            key = new KeyParameter(K, t_len, t_len);
            ICipherParameters parms = new ParametersWithIV(key, IV);
            IBlockCipherPadding padding = new Pkcs7Padding();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), padding);
            cipher.Reset();

            cipher.Init(true, parms);

            byte[] rgbOut = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, rgbOut, 0);
            len += cipher.DoFinal(rgbOut, len);

            rgbEncrypted = new byte[len];
            Array.Copy(rgbOut, rgbEncrypted, len);

            KeyParameter macKey = new KeyParameter(K, 0, t_len);

            //  HMAC AAD
            //  HMAC IV
            //  HMAC ciphertext
            //  HMAC 64bit int = cbit(AAD)
            byte[] rgbAL = new byte[8];
            byte[] rgbAAD = CreateAAD();

            int cbAAD = rgbAAD.Length * 8;
            for (int i = 7; i > 0; i--) {
                rgbAL[i] = (byte) (cbAAD % 256);
                cbAAD = cbAAD / 256;
                if (cbAAD == 0) break;
            }

            HMac hmac = new HMac(new Sha256Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.Init(macKey);

            hmac.BlockUpdate(rgbAAD, 0, rgbAAD.Length);
            hmac.BlockUpdate(IV, 0, IV.Length);
            hmac.BlockUpdate(rgbEncrypted, 0, rgbEncrypted.Length);
            hmac.BlockUpdate(rgbAL, 0, rgbAL.Length);
            hmac.DoFinal(resBuf, 0);

            Array.Resize(ref resBuf, t_len);
            tag = resBuf;

            return K;
        }

        private void AES_CBC_MAC_Decrypt(string alg, byte[] K)
        {
            KeyParameter key;

            int t_len;

            switch (alg) {
            case "A128CBC-HS256":
                t_len = 16;
                break;

            case "A192CBC-HS256":
                t_len = 24;
                break;

            case "A256CBC-HS256":
                t_len = 32;
                break;

            default:
                throw new JOSE_Exception("Internal error");
            }
 
            KeyParameter macKey = new KeyParameter(K, 0, t_len);
            key = new KeyParameter(K, t_len, t_len);
            bool fError = false;
 
            //  HMAC AAD
            //  HMAC IV
            //  HMAC ciphertext
            //  HMAC 64bit int = cbit(AAD)
            byte[] rgbAL = new byte[8];
            byte[] rgbAAD = CreateAAD();

            int cbAAD = rgbAAD.Length * 8;
            for (int i = 7; i > 0; i--) {
                rgbAL[i] = (byte) (cbAAD % 256);
                cbAAD = cbAAD / 256;
                if (cbAAD == 0) break;
            }

            HMac hmac = new HMac(new Sha256Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.Init(macKey);

            hmac.BlockUpdate(rgbAAD, 0, rgbAAD.Length);
            hmac.BlockUpdate(IV, 0, IV.Length);
            hmac.BlockUpdate(rgbEncrypted, 0, rgbEncrypted.Length);
            hmac.BlockUpdate(rgbAL, 0, rgbAL.Length);
            hmac.DoFinal(resBuf, 0);

            if (t_len != tag.Length) fError = true;
            for (int i = 0; i < t_len; i++) if (resBuf[i] != tag[i]) fError = true;


            ICipherParameters parms = new ParametersWithIV(key, IV);
            IBlockCipherPadding padding = new Pkcs7Padding();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), padding);
            cipher.Reset();

            cipher.Init(false, parms);

            byte[] rgbOut = new byte[cipher.GetOutputSize(rgbEncrypted.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, rgbOut, 0);
            len += cipher.DoFinal(rgbOut, len);

            rgbContent = new byte[len];
            if (fError) throw new JOSE_Exception("Does not validate");
            Array.Copy(rgbOut, rgbContent, len);
        }

        private byte[] AES_CCM(string alg, byte[] K)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesFastEngine());
            KeyParameter ContentKey;
            int cbitTag = 64;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            IV = new byte[96 / 8];
            s_PRNG.NextBytes(IV);

            ContentKey = new KeyParameter(K);

            //  Build the object to be hashed

            byte[] A = new byte[0];
            if (objProtected != null) {
                A = UTF8Encoding.UTF8.GetBytes( objProtected.ToString());
            }

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            Array.Resize(ref C, C.Length - (128 / 8) + (cbitTag / 8));
            rgbEncrypted = C;

            return K;
        }
 
    }

    public enum RecipientType
    {
        direct = 1, keyAgree = 2, keyTransport = 3, keyWrap = 4, keyAgreeDirect = 5, keyTransportAndWrap = 6, password = 7
    }

    public class Recipient : Message
    {
        byte[] rgbEncrypted;
        byte[] rgbContent;
        RecipientType m_recipientType;
        Key m_key;
        Key m_senderKey = null;

        public Recipient() { }

        public Recipient(Key key, string algorithm = null, EncryptMessage msg = null)
        {
            if (algorithm != null) {
                switch (algorithm) {
                case "dir":  // Direct encryption mode
                    if (key.AsString("kty") != "oct") throw new JOSE_Exception("Invalid parameters");
                    m_recipientType = RecipientType.direct;
                    break;

                case "ECDH-ES":
#if DEBUG
                case "ECDH-SS":
#endif // DEBUG
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JOSE_Exception("Invalid Parameters");
                    m_recipientType = RecipientType.keyAgreeDirect;
                    break;

                case "RSA1_5":
                case "RSA-OAEP":
                case "RSA-OAEP-256":
                    if (key.AsString("kty") != "RSA") throw new JOSE_Exception("Invalid Parameter");
                    m_recipientType = RecipientType.keyTransport;
                    break;

                case "A128KW":
                case "A192KW":
                case "A256KW":
                case "A128GCMKW":
                case "A192GCMKW":
                case "A256GCMKW":
                    if (key.AsString("kty") != "oct") throw new JOSE_Exception("Invalid Parameter");
                    m_recipientType = RecipientType.keyWrap;
                    break;

                case "ECDH-ES+A128KW":
                case "ECDH-ES+A192KW":
                case "ECDH-ES+A256KW":
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new JOSE_Exception("Invalid Parameter");
                    m_recipientType = RecipientType.keyAgree;
                    break;

                case "PBES2-HS256+A128KW":
                case "PBES2-HS384+A192KW":
                case "PBES2-HS512+A256KW":
                    if (key.AsString("kty") != "oct") throw new JOSE_Exception("Invalid Parameter");
                    m_recipientType = RecipientType.password;
                    break;

                default:
                    throw new JOSE_Exception("Unrecognized recipient algorithm");
                }
                m_key = key;
                if (FindAttr("alg", msg) == null) {
                    AddUnprotected("alg", algorithm);
                }
            }
            else {
                switch (key.AsString("kty")) {
                case "oct":
                    m_recipientType = RecipientType.keyWrap;
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
                        throw new JOSE_Exception("Key size does not match any algorthms");
                    }
                    break;

                case "RSA":
                    m_recipientType = RecipientType.keyTransport;
                    algorithm = "RSA-OAEP-256";
                    break;

                case "EC":
                    m_recipientType = RecipientType.keyAgree;
                    algorithm = "ECDH-ES+A128KW";
                    break;
                }
                if (FindAttr("alg", msg) == null) {
                    AddUnprotected("alg", algorithm);
                }
                m_key = key;
            }

            if (key.ContainsName("use")) {
                string usage = key.AsString("use");
                if (usage != "enc") throw new JOSE_Exception("Key cannot be used for encrytion");
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
                if (!validUsage) throw new JOSE_Exception("Key cannot be used for encryption");
            }

            if (key.ContainsName("kid") && (FindAttr("kid", msg) == null)) {
                AddUnprotected("kid", key.AsString("kid"));
            }
        }

        public RecipientType recipientType { get { return m_recipientType; } }

        new public void DecodeFromJSON(JSON json)
        {

            if (json.ContainsKey("header")) {
                objUnprotected = json["header"];
            }

            if (json.ContainsKey("encrypted_key")) {
                rgbEncrypted = base64urldecode(json["encrypted_key"].AsString());
            }
        }

        public byte[] Decrypt(Key key, int cbitKey, EncryptMessage msg)
        {
            string alg = null;

            alg = FindAttr("alg", msg).AsString();

            switch (alg) {
            case "dir":
                if (key.AsString("kty") != "oct") return null;
                return key.AsBytes("k");

            case "ECDH-ES": {
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) return null;

                    byte[] secret = ECDH(key, msg);
                    byte[] kwKey = KDF(secret, msg, cbitKey, FindAttr("enc", msg).AsString());
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
            case "PBES2-HS512+A256KW": 
                {
                    if (key.AsString("kty") != "oct") return null;
                    byte[] saltInput = base64urldecode( FindAttr("p2s", msg).AsString());
                    byte[] algBytes = UTF8Encoding.UTF8.GetBytes(alg);
                    byte[] salt = new byte[alg.Length + 1 + saltInput.Length];
                    Array.Copy(algBytes, salt, algBytes.Length);
                    Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);
                    int iterCount = FindAttr("p2c", msg).AsInteger() ;

                    byte[] rgbSecret = PBKF2(key.AsBytes("k"), salt, iterCount, 256 / 8, new Sha512Digest());

                    return AES_KeyWrap(rgbSecret);
                }

            case "RSA-OAEP-256":
            case "RSA-OAEP": {
                IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), alg == "RSA-OAEP" ? (IDigest) new Sha1Digest() : new Sha256Digest());
                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(key.AsBigInteger("n"), key.AsBigInteger("e"), key.AsBigInteger("d"), key.AsBigInteger("p"), key.AsBigInteger("q"), key.AsBigInteger("dp"), key.AsBigInteger("dq"), key.AsBigInteger("qi"));

                cipher.Init(false, prv);
                byte[] outBytes = cipher.ProcessBlock(rgbEncrypted, 0, rgbEncrypted.Length);

                return outBytes;
                }

            case "ECDH-ES+A128KW": {
                    if ((key.AsString("kty") != "EC") && (key.AsString("kty") !="OKP")) return null;

                    byte[] secret = ECDH(key, msg);
                    byte[] kwKey = KDF(secret, msg, 128, FindAttr("alg", msg).AsString());
                    return AES_KeyWrap(kwKey);
                }
            
            case "ECDH-ES+A192KW": {
                    if (key.AsString("kty") != "EC") return null;

                    byte[] secret = ECDH(key, msg);
                    byte[] kwKey = KDF(secret, msg, 192, FindAttr("alg", msg).AsString());
                    return AES_KeyWrap(kwKey);
                }

            case "ECDH-ES+A256KW": 
                {
                    if (key.AsString("kty") != "EC") return null;

                    byte[] secret = ECDH(key, msg);
                    byte[] kwKey = KDF(secret, msg, 256, FindAttr("alg", msg).AsString());
                    return AES_KeyWrap(kwKey);
                }

            case "RSA1_5": 
                {
                    if (key.AsString("kty") != "RSA") return null;

                    IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());
                    RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(key.AsBigInteger("n"), key.AsBigInteger("e"), key.AsBigInteger("d"), key.AsBigInteger("p"), key.AsBigInteger("q"), key.AsBigInteger("dp"), key.AsBigInteger("dq"), key.AsBigInteger("qi"));

                    cipher.Init(false, prv);
                    return cipher.ProcessBlock(rgbEncrypted, 0, rgbEncrypted.Length);
                }
            }

            return null;
        }

        public byte[] GetKey(string alg, EncryptMessage msg)
        {
            if (m_key == null) return null;

            try {
                string keyAlgorithm = m_key.AsString("alg");
                if (alg != keyAlgorithm) throw new JOSE_Exception("Algorithm mismatch between message and key");
            }
            catch (Exception) { }

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
                throw new Exception("NYI");
            }

            string algKeyManagement = FindAttr("alg", msg).AsString();

            switch (algKeyManagement) {
            case "dir":
                if (m_key.AsString("kty") != "oct") throw new Exception("Key and key managment algorithm don't match");
                byte[] rgb = m_key.AsBytes("k");
                if (rgb.Length * 8 != cbitKey) throw new Exception("Incorrect key size");
                return rgb;

            case "ECDH-ES": {
                    if ((m_key.AsString("kty") != "EC") && (m_key.AsString("kty") != "OKP")) throw new Exception("Key and key management algorithm don't match");

                    ECDH_GenerateEphemeral(msg);

                    byte[] rgbSecret = ECDH_GenerateSecret(m_key, msg);

                    return KDF(rgbSecret, msg, cbitKey, alg);
                }

            case "ECDH-SS": {
                    if (m_key.AsString("kty") != "EC") throw new Exception("Key and key managment algorithm don't match");
                    if (FindAttribute("apu") == null) {
                        byte[] rgbAPU = new byte[512 / 8];
                        s_PRNG.NextBytes(rgbAPU);
                        AddUnprotected("apu", new JSON(rgbAPU));
                    }
                    byte[] rgbSecret = ECDH_GenerateSecret(m_key, msg);
                    return KDF(rgbSecret, msg, cbitKey, alg);
                }

            }

            throw new Exception("NYI");
        }

        public JSON EncodeToJSON()
        {
            JSON obj = new JSON();

            // if (rgbEncrypted == null) Encrypt();

            if (objUnprotected.Count > 0) obj.Add("header", objUnprotected); // Add unprotected attributes

            if (rgbEncrypted != null) obj.Add("encrypted_key", base64urlencode(rgbEncrypted));      // Add ciphertext

            return obj;
        }

        public void Encrypt(EncryptMessage msg)
        {
            string alg;      // Get the algorithm that was set.
            byte[] rgbSecret;
            byte[] rgbKey;
            JSON objSalt;
            JSON objIterCount;
            byte[] salt;
            byte[] saltInput;
            byte[] algBytes;

            alg = FindAttr("alg", msg).AsString();

            switch (alg) {
            case "dir":
            case "ECDH-ES":
            case "ECDH-SS":
                break;

            case "A128KW": AES_KeyWrap(128); break;
            case "A192KW": AES_KeyWrap(192); break;
            case "A256KW": AES_KeyWrap(256); break;

            case "RSA1_5": RSA_1_5_KeyWrap(); break;

            case "RSA-OAEP": RSA_OAEP_KeyWrap(new Sha1Digest()); break;
            case "RSA-OAEP-256": RSA_OAEP_KeyWrap(new Sha256Digest()); break;

            case "ECDH-ES+A128KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(m_key, msg);
                rgbKey = KDF(rgbSecret, msg, 128, alg);
                AES_KeyWrap(128, rgbKey);
                break;

            case "ECDH-ES+A192KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(m_key, msg);
                rgbKey = KDF(rgbSecret, msg, 192, alg);
                AES_KeyWrap(192, rgbKey);
                break;

            case "ECDH-ES+A256KW":
                ECDH_GenerateEphemeral(msg);
                rgbSecret = ECDH_GenerateSecret(m_key, msg);
                rgbKey = KDF(rgbSecret, msg, 256, alg);
                AES_KeyWrap(256, rgbKey);
                break;

            case "A128GCMKW": AES_GCM_KeyWrap(128, msg); break;
            case "A192GCMKW": AES_GCM_KeyWrap(192, msg); break;
            case "A256GCMKW": AES_GCM_KeyWrap(256, msg); break;

            case "PBES2-HS256+A128KW":
                objSalt = FindAttribute("p2s");
                if (objSalt == null) {
                    salt = new byte[10];
                    s_PRNG.NextBytes(salt);
                    objSalt = new JSON(salt);
                    AddUnprotected("p2s", objSalt);
                }
                objIterCount = FindAttribute("p2c");
                if (objIterCount == null) {
                    objIterCount = new JSON(8000);
                    AddUnprotected("p2c", objIterCount);
                }
                saltInput = base64urldecode(objSalt.AsString());
                algBytes = UTF8Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKF2(m_key.AsBytes("k"), salt, objIterCount.AsInteger(), 128 / 8, new Sha256Digest());
                AES_KeyWrap(128, rgbKey);
                break;

            case "PBES2-HS384+A192KW":
                objSalt = FindAttribute("p2s");
                if (objSalt == null) {
                    salt = new byte[10];
                    s_PRNG.NextBytes(salt);
                    objSalt = new JSON(salt);
                    AddUnprotected("p2s", objSalt);
                }
                objIterCount = FindAttribute("p2c");
                if (objIterCount == null) {
                    objIterCount = new JSON(8000);
                    AddUnprotected("p2c", objIterCount);
                }
                saltInput = base64urldecode(FindAttr("p2s", msg).AsString());
                algBytes = UTF8Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKF2(m_key.AsBytes("k"), salt, objIterCount.AsInteger(), 192 / 8, new Sha384Digest());
                AES_KeyWrap(192, rgbKey);
                break;

            case "PBES2-HS512+A256KW":
                objSalt = FindAttr("p2s", msg);
                if (objSalt == null) {
                    salt = new byte[10];
                    s_PRNG.NextBytes(salt);
                    objSalt = new JSON(salt);
                    AddUnprotected("p2s", objSalt);
                }
                objIterCount = FindAttr("p2c", msg);
                if (objIterCount == null) {
                    objIterCount = new JSON(8000);
                    AddUnprotected("p2c", objIterCount);
                }
                saltInput = base64urldecode(objSalt.AsString());
                algBytes = UTF8Encoding.UTF8.GetBytes(alg);
                salt = new byte[alg.Length + 1 + saltInput.Length];
                Array.Copy(algBytes, salt, algBytes.Length);
                Array.Copy(saltInput, 0, salt, algBytes.Length + 1, saltInput.Length);

                rgbKey = PBKF2(m_key.AsBytes("k"), salt, objIterCount.AsInteger(), 256 / 8, new Sha512Digest());
                AES_KeyWrap(256, rgbKey);
                break;

            default:
                throw new Exception("Unknown or unsupported algorithm: " + alg);
            }

        }

        public void SetContent(byte[] keyBytes)
        {
            rgbContent = keyBytes;
        }

        public void SetSenderKey(Key senderKey)
        {
            m_senderKey = senderKey;
        }

        private void RSA_1_5_KeyWrap()
        {
            IAsymmetricBlockCipher cipher = new Pkcs1Encoding(new RsaEngine());
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, m_key.AsBigInteger("n"), m_key.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters, s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            rgbEncrypted = outBytes;
        }

        private void RSA_OAEP_KeyWrap(IDigest digest)
        {
            IAsymmetricBlockCipher cipher = new OaepEncoding(new RsaEngine(), digest);
            RsaKeyParameters pubParameters = new RsaKeyParameters(false, m_key.AsBigInteger("n"), m_key.AsBigInteger("e"));

            cipher.Init(true, new ParametersWithRandom(pubParameters, s_PRNG));

            byte[] outBytes = cipher.ProcessBlock(rgbContent, 0, rgbContent.Length);

            rgbEncrypted = outBytes;
        }

        private byte[] ECDH(Key key, EncryptMessage msg)
        {
            if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new Exception("Not an EC or OKP Key");

            JSON epkT = FindAttribute("epk");
            if (epkT == null) {
                epkT = msg.FindAttribute("epk");
                if (epkT == null) throw new Exception("No Ephemeral key");
            }
            Key epk = new Key(epkT);

            if (epk.AsString("crv") != key.AsString("crv")) throw new Exception("not a match of curves");

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
                case "X25519":
                    return COSE.X25519.CalculateAgreement(epk.AsBytes("x"), key.AsBytes("d"));

                default:
                    throw new JOSE_Exception("Unsupported curve");
                }
            }
        }

        private void ECDH_GenerateEphemeral(EncryptMessage msg)
        {
            JSON epk = new JSON();

            if (m_key.AsString("kty") == "EC2") {
                X9ECParameters p = NistNamedCurves.GetByName(m_key.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);

                ECKeyPairGenerator pGen = new ECKeyPairGenerator();
                ECKeyGenerationParameters genParam = new ECKeyGenerationParameters(parameters, s_PRNG);
                pGen.Init(genParam);

                AsymmetricCipherKeyPair p1 = pGen.GenerateKeyPair();

                epk.Add("kty", "EC");
                epk.Add("crv", m_key.AsString("crv"));
                ECPublicKeyParameters priv = (ECPublicKeyParameters) p1.Public;
                epk.Add("x", priv.Q.Normalize().XCoord.ToBigInteger().ToByteArrayUnsigned());
                epk.Add("y", priv.Q.Normalize().YCoord.ToBigInteger().ToByteArrayUnsigned());

            }
            else if (m_key.AsString("kty") == "OKP") {
                switch (m_key.AsString("crv")) {
                case "X25519":
                    COSE.X25519KeyPair item = COSE.X25519.GenerateKeyPair();

                    epk.Add("kty", "OKP");
                    epk.Add("crv", "X25519");
                    epk.Add("x", item.Public);
                    break;

                default:
                    throw new JOSE_Exception("Unknown OPK curve");
                }
            }
            else {
                throw new JOSE_Exception("Internal Error");
            }
            if (msg.FindAttribute("epk", true) != null) msg.AddAttribute("epk", epk, true);
            else if (msg.FindAttribute("epk", false) != null) msg.AddAttribute("epk", epk, false);
            else AddUnprotected("epk", epk);
        }


        private byte[] ECDH_GenerateSecret(Key key, EncryptMessage msg)
        {
            Key epk;

            if ((key.AsString("kty") != "EC") && (key.AsString("kty") != "OKP")) throw new Exception("Not an EC or OKP Key");

            if (m_senderKey != null) {
                epk = m_senderKey;
            }
            else {
                JSON epkT = FindAttr("epk", msg);
                if (epkT == null) throw new Exception("No Ephemeral key");
                epk = new Key(epkT);
            }

            if (epk.AsString("crv") != key.AsString("crv")) throw new Exception("not a match of curves");

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
                case "X25519":
                    return COSE.X25519.CalculateAgreement(epk.AsBytes("x"), key.AsBytes("d"));

                default:
                    throw new JOSE_Exception("Unsupported curve");
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

        private byte[] KDF(byte[] secret, EncryptMessage msg, int cbitKey, string algorithmID)
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

            JSON j = FindAttr("apu", msg);
            if (j != null)  rgbPartyU = Message.base64urldecode(j.AsString());
            
            j = FindAttr("apv", msg);
            if (j != null) rgbPartyV = Message.base64urldecode(j.AsString());

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
                rgb[3] = (byte) ( i+1);
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
            rgbContent = foo.Unwrap(rgbEncrypted, 0, rgbEncrypted.Length);
            return rgbContent;
        }

        private void AES_KeyWrap(int keySize, byte[] rgbKey = null)
        {
            if (rgbKey == null) {
                if (m_key.AsString("kty") != "oct") throw new Exception("Key is not correct type");

                rgbKey = m_key.AsBytes("k");
            }
            if (rgbKey.Length != keySize / 8) throw new Exception("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(true, parameters);
            rgbEncrypted = foo.Wrap(rgbContent, 0, rgbContent.Length);
        }

        private byte[] AES_KeyUnwrap(Key keyObject, int keySize, byte[] rgbKey = null)
        {
            if (keyObject != null) {
                if (keyObject.AsString("kty") != "oct") return null;
                rgbKey = keyObject.AsBytes("k");
            }
            if (rgbKey.Length != keySize / 8) throw new Exception("Key is not the correct size");

            AesWrapEngine foo = new AesWrapEngine();
            KeyParameter parameters = new KeyParameter(rgbKey);
            foo.Init(false, parameters);
            rgbContent = foo.Unwrap(rgbEncrypted, 0, rgbEncrypted.Length);
            return rgbContent;
        }

        private void AES_GCM_KeyWrap(int keySize, EncryptMessage msg)
        {
            if (m_key.AsString("kty") != "oct") throw new Exception("Incorrect key type");
            byte[] keyBytes = m_key.AsBytes("k");
            if (keyBytes.Length != keySize / 8) throw new Exception("Key is not the correct size");

            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(keyBytes);
            byte[] A = new byte[0];
            byte[] IV = new byte[96 / 8];


            s_PRNG.NextBytes(IV);
            if (msg.FindAttribute("iv", true) != null) msg.AddAttribute("iv", Message.base64urlencode(IV), true);
            else if (msg.FindAttribute("iv", false) != null) msg.AddAttribute("iv", Message.base64urlencode(IV), false);
            else objUnprotected.Add("iv", Message.base64urlencode(IV));

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(true, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbContent.Length)];
            int len = cipher.ProcessBytes(rgbContent, 0, rgbContent.Length, C, 0);
            len += cipher.DoFinal(C, len);

            if (len != C.Length) throw new JOSE_Exception("NYI");
            byte[] tag = new byte[128 / 8];
            Array.Copy(C, C.Length - tag.Length, tag, 0, tag.Length);

            if (msg.FindAttribute("tag", true) != null) msg.AddAttribute("tag", Message.base64urlencode(tag), true);
            else if (msg.FindAttribute("tag", false) != null) msg.AddAttribute("tag", Message.base64urlencode(tag), false);
            else objUnprotected.Add("tag", Message.base64urlencode(tag));
            
            rgbEncrypted = C;
            Array.Resize(ref rgbEncrypted, C.Length - tag.Length);
            return;

        }

        private byte[] AESGCM_KeyWrap(byte[] key, EncryptMessage msg)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesFastEngine(), new BasicGcmMultiplier());
            KeyParameter ContentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits
            //  Keywrap says that there is no AAD

            ContentKey = new KeyParameter(key);
            byte[] A = new byte[0];
            byte[] IV = base64urldecode(FindAttr("iv", msg).AsString());
            byte[] tag = base64urldecode(FindAttr("tag", msg).AsString());

            AeadParameters parameters = new AeadParameters(ContentKey, 128, IV, A);

            cipher.Init(false, parameters);
            byte[] C = new byte[cipher.GetOutputSize(rgbEncrypted.Length + tag.Length)];
            int len = cipher.ProcessBytes(rgbEncrypted, 0, rgbEncrypted.Length, C, 0);
            len += cipher.ProcessBytes(tag, 0, tag.Length, C, len);
            len += cipher.DoFinal(C, len);

            return C;
        }

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
            Array.Copy(salt, 0, rgbStart, 0, salt.Length);
            byte[] rgbOutput = new byte[l * hLen];

            for (int i = 1; i <= l; i++) {
                byte[] rgbT = new byte[hLen];
                byte[] rgbH = new byte[hLen];

                hmac.Reset();
                rgbStart[rgbStart.Length-1] = (byte) i;
                hmac.BlockUpdate(rgbStart, 0, rgbStart.Length);
                hmac.DoFinal(rgbH, 0);
                Array.Copy(rgbH, rgbT, rgbH.Length);

                for (int j = 1; j < iterCount; j++) {
                    hmac.Reset();
                    hmac.BlockUpdate(rgbH, 0, rgbH.Length);
                    hmac.DoFinal(rgbH, 0);
                    for (int k = 0; k < rgbH.Length; k++ ) rgbT[k] ^= rgbH[k];
                }

                Array.Copy(rgbT, hLen * (i - 1), rgbOutput, 0, rgbT.Length);
            }

            byte[] rgbOut = new Byte[cOctets];
            Array.Copy(rgbOutput, rgbOut, cOctets);
            return rgbOut;
        }
    }
}
