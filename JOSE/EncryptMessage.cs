using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.IO.Compression;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using PeterO.Cbor;


namespace Com.AugustCellars.JOSE
{
    public class EncryptMessage : Message
    {
        private byte[] _iv;
        protected byte[] _RgbEncrypted;
        protected byte[] _Tag;
        protected byte[] _Aad;
        private string _strProtected;
        public List<Recipient> RecipientList { get; } = new List<Recipient>();

        public void AddRecipient(Recipient recipient)
        {
            RecipientList.Add(recipient);
        }

        protected override void InternalDecodeFromJSON(CBORObject json)
        {
            if (json.ContainsKey("protected")) {
                _strProtected = json["protected"].AsString();
                ProtectedMap = CBORObject.FromJSONString(Encoding.UTF8.GetString(base64urldecode(_strProtected)));
                if (ProtectedMap.Type != CBORType.Map || ProtectedMap.Count == 0) {
                    throw new JoseException("field 'protected' must be a non-empty map");
                }
            }
            else {
                ProtectedMap = CBORObject.NewMap();
            }

            //  Can be absent
            if (json.ContainsKey("unprotected")) {
                UnprotectedMap = json["unprotected"];
                if (UnprotectedMap.Type != CBORType.Map || UnprotectedMap.Count == 0) {
                    throw new JoseException("field 'unprotected' must be a non-empty map");
                }
            }
            else {
                UnprotectedMap = CBORObject.NewMap();
            }

            if (json.ContainsKey("iv")) {
                _iv = base64urldecode(json["iv"].AsString());
            }
            else {
                _iv = null;
            }

            if (json.ContainsKey("aad")) {
                _Aad = base64urldecode(json["aad"].AsString());
                _Aad = Encoding.UTF8.GetBytes(json["aad"].AsString());
            }
            else {
                _Aad = null;
            }

            if (!json.ContainsKey("ciphertext")) {
                throw new JoseException("field 'ciphertext' must be present");
            }

            _RgbEncrypted = base64urldecode(json["ciphertext"].AsString());

            if (json.ContainsKey("tag")) {
                _Tag = base64urldecode(json["tag"].AsString());
            }
            else {
                _Tag = null;
            }

            if (json.ContainsKey("recipients")) {
                CBORObject recips = json["recipients"];
                if (recips.Type != CBORType.Array || recips.Count == 0) {
                    throw new JoseException("field 'recipients' must be a non-empty array");
                }

                bool needHeaders = (ProtectedMap.Count + UnprotectedMap.Count) == 0;
                for (int i = 0; i < recips.Count; i++) {
                    Recipient recipient = new Recipient();
                    recipient.DecodeFromJSON(recips[i]);
                    RecipientList.Add(recipient);

                    if (needHeaders) {
                        if (recipient.ProtectedMap.Count + recipient.UnprotectedMap.Count == 0) {
                            throw new JoseException("One of protected, unprotected or headers must be present for every recipient");
                        }
                    }
                }
            }
            else {
                //  Look at ths as a flattened version
                Recipient recipient = new Recipient();
                recipient.DecodeFromJSON(json);
                RecipientList.Add(recipient);

                if (recipient.ProtectedMap.Count + recipient.UnprotectedMap.Count + ProtectedMap.Count + UnprotectedMap.Count == 0) {
                    throw new JoseException("One of protected, unprotected or headers must be present for every recipient");
                }
            }
        }



        public byte[] Decrypt(Recipient recipientIn)
        {
            //  Get the CEK
            byte[] cek = null;
            int cbitCek;
            string alg;

            try {
                alg = FindAttribute("enc").AsString();
            }
            catch {
                alg = recipientIn.FindAttribute("enc").AsString();
            }

            switch (alg) {
            case "A128GCM":
                cbitCek = 128;
                break;

            case "A192GCM":
                cbitCek = 192;
                break;

            case "A256GCM":
            case "A128CBC-HS256":
                cbitCek = 256;
                break;

            case "A192CBC-HS256":
                cbitCek = 384;
                break;

            case "A256CBC-HS256":
                cbitCek = 512;
                break;

            default:
                throw new JoseException($"Unsupported content encryption algorithm {alg}");
            }

            foreach (Recipient recipient in RecipientList) {
                try {
                    if (recipient == recipientIn) {
                        cek = recipient.Decrypt(cbitCek, this);
                    }
                    else if (recipientIn == null) {
                        cek = recipient.Decrypt(cbitCek, this);
                    }
                }
                catch (Exception) {
                    // ignored
                }
                if (cek != null) break;
            }

            if (cek == null) {
                //  Generate a null CEK
                throw new JoseException("No Recipient information found.");
            }


            switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                AES_GCM_Decrypt(cek);
                break;

            case "A128CBC-HS256":
            case "A192CBC-HS256":
            case "A256CBC-HS256":
                AES_CBC_MAC_Decrypt(alg, cek);
                break;
            }

            //  Check for compression now

            if (FindAttribute("zip") != null) {
                MemoryStream stm = new MemoryStream(payload);
                DeflateStream zipStm = new DeflateStream(stm, CompressionMode.Decompress);
                MemoryStream stm2 = new MemoryStream();
                zipStm.CopyTo(stm2);

                payload = stm2.GetBuffer();

                zipStm.Dispose();
            }

            return payload;
        }


        /// <inheritdoc />
        protected override string InternalEncodeCompressed()
        {
            CBORObject obj3;
            CBORObject objRecip = null;
            string str = "";

            if (RecipientList.Count() != 1) {
                throw new JoseException("Compact encoding cannot have more than one recipient");
            }


            if (_Aad != null) {
                throw new JoseException("Compact encoding cannot have additional authenticated data");
            }

            if (RecipientList[0].UnprotectedMap.Count != 0) {
                if (_RgbEncrypted == null) {
                    foreach (CBORObject o in RecipientList[0].UnprotectedMap.Keys) {
                        ProtectedMap.Add(o, RecipientList[0].UnprotectedMap[o]);
                    }
                    RecipientList[0].UnprotectedMap.Clear();
                }
            }

            ForceArray(true);
            obj3 = EncodeToJSON();

            if (obj3.ContainsKey("recipients")) {
                objRecip = obj3["recipients"][0];
            }

            if (obj3.ContainsKey("aad"))
            {
                throw new JoseException("Compact encoding cannot have additional authenticated data");
            }

            if (objRecip != null && objRecip.ContainsKey("header")) throw new JoseException("Compact encoding cannot have recipient header data");

            if (obj3.ContainsKey("protected")) str += obj3["protected"].AsString();
            str += ".";
            if (obj3.ContainsKey("unprotected")) throw new JoseException("Compact encoding cannot have unprotected attributes");

            if (objRecip != null && objRecip.ContainsKey("encrypted_key")) str += objRecip["encrypted_key"].AsString();
            str += ".";
            if (obj3.ContainsKey("iv")) str += obj3["iv"].AsString();
            str += ".";
            if (obj3.ContainsKey("ciphertext")) str += obj3["ciphertext"].AsString();
            str += ".";
            if (obj3.ContainsKey("tag")) str += obj3["tag"].AsString();

            return str;
        }

        /// <inheritdoc />
        protected override CBORObject InternalEncodeToJSON(bool fCompact)
        {
            CBORObject obj = CBORObject.NewMap();

            if (_RgbEncrypted == null) Encrypt();

            if (ProtectedMap.Count > 0) {
                obj.Add("protected", base64urlencode(Encoding.UTF8.GetBytes( ProtectedMap.ToString())));
            }

            if (UnprotectedMap.Count > 0) obj.Add("unprotected", UnprotectedMap); // Add unprotected attributes

            if (_iv != null) obj.Add("iv", base64urlencode( _iv ));      // Add iv

            if (_Aad != null) obj.Add("aad", Encoding.UTF8.GetString(_Aad));

            if (_RgbEncrypted != null) obj.Add("ciphertext", base64urlencode(_RgbEncrypted));      // Add ciphertext
            obj.Add("tag", base64urlencode(_Tag));

            if (RecipientList.Count > 0) {
                    CBORObject recipients = CBORObject.NewArray();

                    foreach (Recipient key in RecipientList) {
                        CBORObject j = key.EncodeToJSON();
                        if ((j != null) && (j.Count != 0)) recipients.Add(j);
                    }

                    if (fCompact){
                        if (recipients.Count != 1) {
                            throw new JoseException("Compact encoding must be for one recipient");
                        }
                        if (recipients[0].ContainsKey("encrypted_key")) {
                            obj.Add("encrypted_key", recipients[0]["encrypted_key"]);
                        }

                        if (recipients[0].ContainsKey("header")) {
                            obj.Add("header", recipients[0]["header"]);
                        }
                    }
                    else {
                        if (recipients.Count > 0) obj.Add("recipients", recipients);
                    }
            
            }
            else {
                throw new JoseException("Must have one or more recipients");
            }
            return obj;
        }

        /// <summary>
        /// Encrypt the message based on attributes and recipients.
        /// </summary>
        public virtual void Encrypt()
        {
            string alg = null;

            //  Get the algorithm we are using - the default is AES GCM

            try {
                alg = FindAttribute("enc").AsString();
            }
            catch {

                foreach (Recipient r in RecipientList) {
                    CBORObject alg2 = r.FindAttribute("enc");
                    if (alg2 != null) {
                        if (alg2.Type != CBORType.TextString || (alg != null && alg != alg2.AsString())) {
                            throw new JoseException("Multiple content encryption algorithms have been specified.");
                        }
                        alg = alg2.AsString();
                    }
                }

                if (alg == null) {
                    throw new JoseException("Content encryption algorithm has not been specified.");
                }
            }

            byte[] contentKey = null;

            //  Determine if we are doing a direct encryption
            int recipientTypes = 0;

            if (RecipientList.Count == 0) {
                throw new JoseException("Must have at least one recipient for the message");
            }

            foreach (Recipient key in RecipientList) {
                switch (key.RecipientType) {
                case RecipientType.Direct:
                case RecipientType.KeyAgreeDirect:
                    if ((recipientTypes & 1) != 0) throw new JoseException("It is not legal to have two direct recipients in a message");
                    recipientTypes |= 1;
                    contentKey = key.GetKey(alg, this);
                    break;

                default:
                    recipientTypes |= 2;
                    break;
                }
            }

            if (recipientTypes == 3) throw new JoseException("It is not legal to mix direct and indirect recipients in a message");

            if (contentKey == null) {
                switch (alg) {
                case "A128GCM":
                case "AES-128-CCM-64":
                    contentKey = new byte[128 / 8];
                    break;

                case "A192GCM":
                case "AES192GCM":
                    contentKey = new byte[192 / 8];
                    break;

                case "A256GCM":
                case "AES256GCM":
                    contentKey = new byte[256 / 8];
                    break;

                case "A128CBC-HS256":
                    contentKey = new byte[2*128 / 8];
                    break;

                case "A192CBC-HS256":
                    contentKey = new byte[2*192 / 8];
                    break;

                case "A256CBC-HS256":
                    contentKey = new byte[2*256 / 8];
                    break;

                default:
                    throw new JoseException($"Unrecognized content encryption algorithm '{alg}'");
                }

                s_PRNG.NextBytes(contentKey);
            }

            foreach (Recipient key in RecipientList) {
                key.SetContent(contentKey);
                key.Encrypt(this);
            }

            //  Encode the protected attributes if there are any

            if (ProtectedMap.Count > 0) {
                _strProtected = base64urlencode(Encoding.UTF8.GetBytes(ProtectedMap.ToString()));
            }

            byte[] saveContent = payload;
            if (ProtectedMap.ContainsKey("zip")) {
                MemoryStream stm2 = new MemoryStream();
                DeflateStream zipStm = new DeflateStream(stm2, CompressionMode.Compress);

                zipStm.Write(payload, 0, payload.Length);
                zipStm.Close();

                payload = stm2.GetBuffer();
            }

            switch (alg) {
            case "A128GCM":
            case "A192GCM":
            case "A256GCM":
                AES_GCM_Encrypt(contentKey);
                break;

            case "AES-128-CCM-64":
                AES_CCM(contentKey);
                break;

            case "A128CBC-HS256":
            case "A192CBC-HS256":
            case "A256CBC-HS256":
                AES_CBC_MAC_Encrypt(alg, contentKey);
                break;

            default:
                throw new JoseException("Internal Error:  We should never get here.");
            }

            payload = saveContent;
        }


        public void SetAad(byte[] data)
        {
            _Aad = Encoding.UTF8.GetBytes( base64urlencode(data));
        }

        public void SetAad(string text)
        {
            SetAad( Encoding.UTF8.GetBytes(text));
        }


        private byte[] CreateAad()
        {
            int cb = 0;

            if (_strProtected != null) {
                cb = _strProtected.Length;
            }
            if (_Aad != null) {
                cb += _Aad.Length + 1;
            }

            byte[] rgbOut = new byte[cb];
            cb = 0;

            if (_strProtected != null) {
                byte[] rgbX = Encoding.UTF8.GetBytes(_strProtected);
                Array.Copy(rgbX, rgbOut, rgbX.Length);
                cb = rgbX.Length;
            }

            if (_Aad != null) {
                rgbOut[cb] = 0x2e;
                Array.Copy(_Aad, 0, rgbOut, cb+1, _Aad.Length);
            }

            return rgbOut;
        }

        private void AES_GCM_Encrypt(byte[] k)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter contentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            _iv = new byte[96 / 8];
            s_PRNG.NextBytes(_iv);

            contentKey = new KeyParameter(k);

            //  Build the object to be hashed

            byte[] a = CreateAad();
            AeadParameters parameters = new AeadParameters(contentKey, 128, _iv, a);

            cipher.Init(true, parameters);

            byte[] c = new byte[cipher.GetOutputSize(payload.Length)];
            int len = cipher.ProcessBytes(payload, 0, payload.Length, c, 0);
            cipher.DoFinal(c, len);

            _RgbEncrypted = c;
            _Tag = cipher.GetMac();
            Array.Resize(ref _RgbEncrypted, _RgbEncrypted.Length - _Tag.Length);
        }

        private void AES_GCM_Decrypt(byte[] k)
        {
            GcmBlockCipher cipher = new GcmBlockCipher(new AesEngine(), new BasicGcmMultiplier());
            KeyParameter contentKey;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            contentKey = new KeyParameter(k);

            byte[] a = CreateAad();

            AeadParameters parameters = new AeadParameters(contentKey, 128, _iv, a);

            cipher.Init(false, parameters);
            byte[] c = new byte[cipher.GetOutputSize(_RgbEncrypted.Length + _Tag.Length)];
            int len = cipher.ProcessBytes(_RgbEncrypted, 0, _RgbEncrypted.Length, c, 0);
            len += cipher.ProcessBytes(_Tag, 0, _Tag.Length, c, len);
            cipher.DoFinal(c, len);

            payload = c;

        }

        private void AES_CBC_MAC_Encrypt(string alg, byte[] k)
        {
            KeyParameter key;

            int tLen;

            switch (alg) {
            case "A128CBC-HS256":
                tLen = 16;
                break;

            case "A192CBC-HS256":
                tLen = 24;
                break;

            case "A256CBC-HS256":
                tLen = 32;
                break;

            default:
                throw new JoseException("Internal error");
            }

            _iv = new byte[128 / 8];
            s_PRNG.NextBytes(_iv);

            key = new KeyParameter(k, tLen, tLen);
            ICipherParameters parms = new ParametersWithIV(key, _iv);
            IBlockCipherPadding padding = new Pkcs7Padding();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), padding);
            cipher.Reset();

            cipher.Init(true, parms);

            byte[] rgbOut = new byte[cipher.GetOutputSize(payload.Length)];
            int len = cipher.ProcessBytes(payload, 0, payload.Length, rgbOut, 0);
            len += cipher.DoFinal(rgbOut, len);

            _RgbEncrypted = new byte[len];
            Array.Copy(rgbOut, _RgbEncrypted, len);

            KeyParameter macKey = new KeyParameter(k, 0, tLen);

            //  HMAC AAD
            //  HMAC IV
            //  HMAC ciphertext
            //  HMAC 64bit int = cbit(AAD)
            byte[] rgbAl = new byte[8];
            byte[] rgbAad = CreateAad();

            int cbAad = rgbAad.Length * 8;
            for (int i = 7; i > 0; i--) {
                rgbAl[i] = (byte) (cbAad % 256);
                cbAad /= 256;
                if (cbAad == 0) break;
            }

            HMac hmac = new HMac(new Sha256Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.Init(macKey);

            hmac.BlockUpdate(rgbAad, 0, rgbAad.Length);
            hmac.BlockUpdate(_iv, 0, _iv.Length);
            hmac.BlockUpdate(_RgbEncrypted, 0, _RgbEncrypted.Length);
            hmac.BlockUpdate(rgbAl, 0, rgbAl.Length);
            hmac.DoFinal(resBuf, 0);

            Array.Resize(ref resBuf, tLen);
            _Tag = resBuf;
        }

        private void AES_CBC_MAC_Decrypt(string alg, byte[] k)
        {
            KeyParameter key;

            int tLen;

            switch (alg) {
            case "A128CBC-HS256":
                tLen = 16;
                break;

            case "A192CBC-HS256":
                tLen = 24;
                break;

            case "A256CBC-HS256":
                tLen = 32;
                break;

            default:
                throw new JoseException("Internal error");
            }
 
            KeyParameter macKey = new KeyParameter(k, 0, tLen);
            key = new KeyParameter(k, tLen, tLen);
            bool fError = false;
 
            //  HMAC AAD
            //  HMAC IV
            //  HMAC ciphertext
            //  HMAC 64bit int = cbit(AAD)
            byte[] rgbAl = new byte[8];
            byte[] rgbAad = CreateAad();

            int cbAad = rgbAad.Length * 8;
            for (int i = 7; i > 0; i--) {
                rgbAl[i] = (byte) (cbAad % 256);
                cbAad /= 256;
                if (cbAad == 0) break;
            }

            HMac hmac = new HMac(new Sha256Digest());
            byte[] resBuf = new byte[hmac.GetMacSize()];
            hmac.Init(macKey);

            hmac.BlockUpdate(rgbAad, 0, rgbAad.Length);
            hmac.BlockUpdate(_iv, 0, _iv.Length);
            hmac.BlockUpdate(_RgbEncrypted, 0, _RgbEncrypted.Length);
            hmac.BlockUpdate(rgbAl, 0, rgbAl.Length);
            hmac.DoFinal(resBuf, 0);

            if (tLen != _Tag.Length) fError = true;
            for (int i = 0; i < tLen; i++) {
                if (resBuf[i] != _Tag[i]) fError = true;
            }


            ICipherParameters parms = new ParametersWithIV(key, _iv);
            IBlockCipherPadding padding = new Pkcs7Padding();
            BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), padding);
            cipher.Reset();

            cipher.Init(false, parms);

            byte[] rgbOut = new byte[cipher.GetOutputSize(_RgbEncrypted.Length)];
            int len = cipher.ProcessBytes(_RgbEncrypted, 0, _RgbEncrypted.Length, rgbOut, 0);
            len += cipher.DoFinal(rgbOut, len);

            payload = new byte[len];
            if (fError) throw new JoseException("Does not validate");
            Array.Copy(rgbOut, payload, len);
        }

        private void AES_CCM(byte[] k)
        {
            CcmBlockCipher cipher = new CcmBlockCipher(new AesEngine());
            KeyParameter contentKey;
            int cbitTag = 64;

            //  The requirements from JWA
            //  IV is 96 bits
            //  Authentication tag is 128 bits
            //  key sizes are 128, 192 and 256 bits

            _iv = new byte[96 / 8];
            s_PRNG.NextBytes(_iv);

            contentKey = new KeyParameter(k);

            //  Build the object to be hashed

            byte[] a = new byte[0];
            if (ProtectedMap != null) {
                a = Encoding.UTF8.GetBytes( ProtectedMap.ToString());
            }

            AeadParameters parameters = new AeadParameters(contentKey, 128, _iv, a);

            cipher.Init(true, parameters);

            byte[] c = new byte[cipher.GetOutputSize(payload.Length)];
            int len = cipher.ProcessBytes(payload, 0, payload.Length, c, 0);
            cipher.DoFinal(c, len);

            Array.Resize(ref c, c.Length - (128 / 8) + (cbitTag / 8));
            _RgbEncrypted = c;
        }
 
    }

}
