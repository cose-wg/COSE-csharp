using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Security;

namespace JOSE
{
    public abstract class Message : Attributes
    {
        public static SecureRandom s_PRNG = new SecureRandom();

  
        public static void SetPRNG(SecureRandom prng)
        {
            s_PRNG = prng;
        }

        public static Message DecodeFromString(string messageData)
        {
            JSON message = new JSON();

            //  We need to figure out if this is the compact or one of the JSON encoded versions.
            //  We guess this is going to be based on the first character - either it is a '{' or something else

            if (messageData[0] == '{') {
                message = JSON.Parse(messageData);
            }
            else {
                //  Split the string based on periods
                string[] rgData = messageData.Split('.');

                if (rgData.Length == 3) {
                    message = new JSON();

                    if (rgData[1].Length > 0) message.Add("payload", rgData[1]);

                    JSON signature = new JSON();
                    signature.Add("protected", rgData[0]);
                    signature.Add("signature", rgData[2]);

                    JSON sigs = new JSON();
                    sigs.Add(signature);
                    message.Add("signatures", sigs);
                }
                else if (rgData.Length == 5) {
                    message = new JSON();
                    message.Add("protected", rgData[0]);
                    message.Add("iv", rgData[2]);
                    message.Add("ciphertext", rgData[3]);
                    message.Add("tag", rgData[4]);

                    JSON recip = new JSON();
                    recip.Add("encrypted_key", rgData[1]);

                    JSON recips = new JSON();
                    recips.Add(recip);

                    message.Add("recipients", recips);
                }
            }

            if (message.ContainsKey("iv")) {
                EncryptMessage msgx = new EncryptMessage();
                msgx.DecodeFromJSON(message);
                return msgx;
            }

            return new SignMessage(message);

        }

        public static Message DecodeFromJSON(JSON message)
        {
            if (message.ContainsKey("iv")) {
                EncryptMessage msgx = new EncryptMessage();
                msgx.DecodeFromJSON(message);
                return msgx;
            }

            return new SignMessage(message);
        }

        // abstract public byte[] EncodeToBytes();

        static public byte[] base64urldecode(string arg)
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

        static public string base64urlencode(byte[] arg)
        {
            string s = Convert.ToBase64String(arg); // Regular base64 encoder
            s = s.Split('=')[0]; // Remove any trailing '='s
            s = s.Replace('+', '-'); // 62nd char of encoding
            s = s.Replace('/', '_'); // 63rd char of encoding
            return s;
        }
 
    }

        public class Attributes
        {
            protected JSON objProtected = new JSON();
            protected JSON objUnprotected = new JSON();
            protected bool forceAsArray = false;

            public void AddAttribute(string name, string value, bool fProtected)
            {
                if (fProtected) AddProtected(name, value);
                else AddUnprotected(name, value);
            }

            public void AddAttribute(string name, JSON value, bool fProtected)
            {
                if (fProtected) AddProtected(name, value);
                else AddUnprotected(name, value);
            }

            public void AddProtected(string name, string value)
            {
                AddProtected(name, JSON.FromObject(value));
            }

            public void AddProtected(string name, JSON value)
            {
                if (objUnprotected.ContainsKey(name)) objUnprotected.Remove(name);
                if (objProtected.ContainsKey(name)) objProtected[name] = value;
                else objProtected.Add(name, value);
            }

            public void AddUnprotected(string name, string value)
            {
                AddUnprotected(name, JSON.FromObject(value));
            }

            public void AddUnprotected(string name, JSON value)
            {
                if (objProtected.ContainsKey(name)) objProtected.Remove(name);
                if (objUnprotected.ContainsKey(name)) objUnprotected[name] = value;
                else objUnprotected.Add(name, value);
            }

#if false
            public byte[] EncodeProtected()
            {
                byte[] A = new byte[0];
                if (objProtected != null) A = objProtected.EncodeToBytes();
                return A;
            }
#endif


            public JSON FindAttribute(string name)
            {
                if (objProtected.nodeType == JsonType.map && objProtected.ContainsKey(name)) return objProtected[name];
                if (objUnprotected.nodeType == JsonType.map && objUnprotected.ContainsKey(name)) return objUnprotected[name];
                return null;
            }

            public JSON FindAttribute(string name, bool fProtected)
            {
                if (fProtected && objProtected.nodeType == JsonType.map && objProtected.ContainsKey(name)) return objProtected[name];
                if (!fProtected && objUnprotected.nodeType == JsonType.map && objUnprotected.ContainsKey(name)) return objUnprotected[name];
                return null;
            }

            public JSON FindAttr(string key, Attributes msg)
            {
                JSON j = FindAttribute(key);
                if ((j == null) && (msg != null)) j = msg.FindAttribute(key);
                return j;
            }

            public void ForceArray(bool f) { forceAsArray = f; }

            public void ClearProtected()
            {
                objProtected.Clear();
            }

            public void ClearUnprotected()
            {
                objUnprotected.Clear();
            }
        }

        public class JOSE_Exception : Exception
        {
            public JOSE_Exception(string str) : base(str) { }
        }
    }


