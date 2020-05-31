using System;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public abstract class Message : Attributes
    {
        public static SecureRandom s_PRNG = new SecureRandom();

        public byte[] payloadB64;
        public byte[] payload;

        public static void SetPRNG(SecureRandom prng)
        {
            s_PRNG = prng;
        }

        #region Encode Functions

        public string Encode()
        {
            return InternalEncodeToJSON(false).ToJSONString();
        }

        public string EncodeFlattened()
        {
            return InternalEncodeToJSON(true).ToJSONString();
        }

        public string EncodeCompressed()
        {
            return InternalEncodeCompressed();
        }

        public CBORObject EncodeToJSON(bool compressed = false)
        {
            return InternalEncodeToJSON(compressed);
        }


        protected abstract CBORObject InternalEncodeToJSON(bool fCompact);

        protected abstract string InternalEncodeCompressed();

        #endregion

        public static Message DecodeFromString(string messageData)
        {
            CBORObject message;

            //  We need to figure out if this is the compact or one of the JSON encoded versions.
            //  We guess this is going to be based on the first character - either it is a '{' or something else

            if (messageData[0] == '{') {
                message =  CBORObject.FromJSONString(messageData);
            }
            else {
                //  Split the string based on periods
                string[] rgData = messageData.Split('.');

                if (rgData.Length == 3) {
                    message = CBORObject.NewMap();

                    if (rgData[1].Length > 0) message.Add("payload", rgData[1]);

                    CBORObject signature = CBORObject.NewMap();
                    signature.Add("protected", rgData[0]);
                    signature.Add("signature", rgData[2]);

                    CBORObject sigs = CBORObject.NewArray();
                    sigs.Add(signature);
                    message.Add("signatures", sigs);
                }
                else if (rgData.Length == 5) {
                    message = CBORObject.NewMap();
                    message.Add("protected", rgData[0]);
                    message.Add("iv", rgData[2]);
                    message.Add("ciphertext", rgData[3]);
                    message.Add("tag", rgData[4]);

                    CBORObject recip = CBORObject.NewMap();
                    recip.Add("encrypted_key", rgData[1]);

                    CBORObject recips = CBORObject.NewArray();
                    recips.Add(recip);

                    message.Add("recipients", recips);
                }
                else {
                    throw new JoseException("There are not the correct number of dots.");
                }
            }

            return DecodeFromJSON(message);
        }

        protected abstract void InternalDecodeFromJSON(CBORObject cbor);


        public static Message DecodeFromJSON(CBORObject message)
        {
            if (message.ContainsKey("ciphertext")) {
                EncryptMessage msgx = new EncryptMessage();
                msgx.InternalDecodeFromJSON(message);
                return msgx;
            }

            SignMessage signMessage = new SignMessage();
            signMessage.InternalDecodeFromJSON(message);
            return signMessage;
        }

        public void SetContent(byte[] rgbContent)
        {
            payload = rgbContent;
            payloadB64 = Encoding.UTF8.GetBytes(base64urlencode(payload));
        }

        public void SetContent(string value)
        {
            payload = Encoding.UTF8.GetBytes(value);
            payloadB64 = Encoding.UTF8.GetBytes(base64urlencode(payload));
        }

        public string GetContentAsString()
        {
            if (payload == null) throw new JoseException("No content to be found");
            return Encoding.UTF8.GetString(payload);
        }


        // abstract public byte[] EncodeToBytes();

        public static byte[] base64urldecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
            case 0: break; // No pad chars in this case
            case 2: s += "=="; break; // Two pad chars
            case 3: s += "="; break; // One pad char
            default: throw new System.Exception(
              "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder

            
        }

        public static string base64urlencode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }
 
    }
}


