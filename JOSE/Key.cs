using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Math;

namespace JOSE
{
    public class Key
    {
        JSON json;

        public Key()
        {
            json = new JSON();
        }

        public Key(JSON jsonIn)
        {
            if (jsonIn.nodeType != JsonType.map) throw new Exception("Invalid key structure");
            json = jsonIn;
        }

        public BigInteger AsBigInteger(string key)
        {
            return ConvertBigNum(json[key].AsString());
        }

        public byte[] AsBytes(string key)
        {
            return Message.base64urldecode(json[key].AsString());
        }

        public string AsString(string key)
        {
            return json[key].AsString();
        }

        public void Add(string key, string value)
        {
            JSON jval = new JSON();
            jval.nodeType = JsonType.text;
            jval.text = value;
            json[key] = jval;
        }

        public Boolean ContainsName(string name)
        {
            return json.ContainsKey(name);
        }

        private Org.BouncyCastle.Math.BigInteger ConvertBigNum(string str)
        {

            byte[] rgb = Message.base64urldecode(str);
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) rgb2[i + 2] = rgb[i];

            return new Org.BouncyCastle.Math.BigInteger(rgb2);
        }

        public static byte[] FromBigNum(Org.BouncyCastle.Math.BigInteger bi)
        {
            byte[] rgbT = bi.ToByteArrayUnsigned();
            return rgbT;
        }
    }

    public class KeySet
    {
        List<Key> keys = new List<Key>();

        public KeySet()
        {
            
        }

        public KeySet(JSON json)
        {
            if (json.nodeType == JsonType.array) {
                for (int i = 0; i < json.Count; i++) { keys.Add(new Key(json[i])); }
            }
            else {
                keys.Add(new Key(json));
            }
        }

        public Key this[int i]
        { get { return keys[i]; } }

        public void Add(Key newKey) 
        {
            keys.Add(newKey);
        }

        public int Count { get { return keys.Count;  } }
    }
}
