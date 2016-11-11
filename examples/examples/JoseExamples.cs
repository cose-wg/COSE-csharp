using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using JOSE;
using Org.BouncyCastle.Crypto.Digests;


namespace examples
{
    public class JoseExamples
    {
        public static void RunTests()
        {
            DirectoryInfo diTop;

            if (false) {
                Console.WriteLine("ProcessFile: ");
                ProcessNestedFile(@"c:\projects\JOSE\test\6.nesting_signatures_and_encryption.json");

                //      PBE_Tests();

                diTop = new DirectoryInfo(@"c:\Projects\JOSE\test\jwe");


                foreach (var fi in diTop.EnumerateFiles()) {
                    Console.WriteLine("Process file: " + fi.Name);
                    ProcessFile(fi.FullName);
                }


                diTop = new DirectoryInfo(@"c:\projects\JOSE\test\jws");
                foreach (var fi in diTop.EnumerateFiles()) {
                    Console.WriteLine("Process file: " + fi.Name);
                    ProcessFile(fi.FullName);

                }
            }
            diTop = new DirectoryInfo(@"c:\projects\JOSE\test\jws-2");
            foreach (var fi in diTop.EnumerateFiles()) {
                Console.WriteLine("Process file: " + fi.Name);
                ProcessFile(fi.FullName);
            }
            diTop = new DirectoryInfo(@"c:\projects\JOSE\test\eddsa");
            foreach (var fi in diTop.EnumerateFiles()) {
                Console.WriteLine("Process file: " + fi.Name);
                ProcessFile(fi.FullName);
            }

        }

        static void ProcessFile(string fileName)
        {
            if (fileName[fileName.Length - 1] == '~') return;
            if (fileName[fileName.Length - 1] == '#') return;

            StreamReader file = File.OpenText(fileName);

            string fileText = file.ReadToEnd();

            JSON control;
            try {
                control = JSON.Parse(fileText);
            }
            catch (Exception e) {
                return;
            }

            if (control["input"].ContainsKey("passport")) {
                ProcessPassport(control);
            }
            else {
                ProcessJSON(control);
            }
        }

        static void ProcessJSON(JSON control)
        {
            KeySet keys = null;

            //  Get the keys

            if (control["input"].ContainsKey("key")) {
                keys = new KeySet(control["input"]["key"]);
            }
            if (control["input"].ContainsKey("pwd")) {
                Key key = new Key();
                key.Add("kty", "oct");
                key.Add("k", Message.base64urlencode(UTF8Encoding.UTF8.GetBytes(control["input"]["pwd"].AsString())));
                keys = new KeySet();
                keys.Add(key);
            }
            if (keys == null) {
                Console.WriteLine("No keys found");
                return;
            }

            //
            //  Check that we can validate each of these items
            //
            //  Start with compact

            if (control["output"].ContainsKey("compact")) {
                Console.WriteLine("    Compact");
                for (int i = 0; i < keys.Count; i++) {
                    Message msg = Message.DecodeFromString(control["output"]["compact"].AsString());

                    CheckMessage(msg, keys[i], control["input"]);

                }

                //
                //  Build a new version of the message
                //

                BuildCompact(control, keys);
            }

            if (control["output"].ContainsKey("json")) {
                Console.WriteLine("     Full");
                for (int i = 0; i < keys.Count; i++) {
                    Message msg = Message.DecodeFromJSON(control["output"]["json"]);

                    CheckMessage(msg, keys[i], control["input"]);
                }
            }

            if (control["output"].ContainsKey("json_flat")) {
                Console.WriteLine("     Flat");
                for (int i = 0; i < keys.Count; i++) {
                    Message msg = Message.DecodeFromJSON(control["output"]["json_flat"]);

                    CheckMessage(msg, keys[i], control["input"]);
                }
            }
        }

        static void ProcessNestedFile(string fileName)
        {
            StreamReader file = File.OpenText(fileName);

            string fileText = file.ReadToEnd();

            JSON control = JSON.Parse(fileText);

            ProcessJSON(control["sign"]);

            ProcessJSON(control["encrypt"]);

        }


        static void CheckMessage(Message msg, Key key, JSON input)
        {
            if (msg.GetType() == typeof(EncryptMessage)) {
                EncryptMessage enc = (EncryptMessage) msg;

                try {
                    enc.Decrypt(key);
                }
                catch (Exception e) { Console.WriteLine("Failed to decrypt " + e.ToString()); return; }

                if (enc.GetContentAsString() != input["plaintext"].AsString()) Console.WriteLine("Plain text does not match");
            }
            else if (msg.GetType() == typeof(SignMessage)) {
                SignMessage sig = (SignMessage) msg;

                try {
                    try {
                        sig.GetContentAsString();
                    }
                    catch (System.Exception e) {
                        sig.SetContent(input["payload"].AsString());
                    }
                    sig.Verify(key);

                    if (sig.GetContentAsString() != input["payload"].AsString()) Console.WriteLine("Plain text does not match");
                }
                catch (Exception e) { Console.WriteLine("Failed to verify " + e.ToString()); return; }
            }
        }

        static void BuildCompact(JSON control, KeySet keys)
        {
            //  Encrypted or Signed?
            if (control.ContainsKey("signing")) {
                JOSE.SignMessage sign = new JOSE.SignMessage();
                JOSE.Signer signer = new JOSE.Signer(keys[0]);

                sign.SetContent(control["input"]["payload"].AsString());
                sign.AddSigner(signer);

                JSON xx = control["signing"]["protected"];
                foreach (string key in xx.Keys) {
                    signer.AddProtected(key, xx[key]);
                }

                string output = sign.EncodeCompact();

                Message msg = Message.DecodeFromString(output);

                CheckMessage(msg, keys[0], control["input"]);

            }
            else if (control.ContainsKey("encrypting_key")) {
                JOSE.EncryptMessage enc = new EncryptMessage();
                JSON xx = control["encrypting_content"]["protected"];
                foreach (string key in xx.Keys) {
                    enc.AddProtected(key, xx[key]);
                }

                JOSE.Recipient recip = new Recipient(keys[0], control["input"]["alg"].AsString(), enc);

                enc.AddRecipient(recip);
                enc.SetContent(control["input"]["plaintext"].AsString());


                string output = enc.EncodeCompact();

                Message msg = Message.DecodeFromString(output);

                CheckMessage(msg, keys[0], control["input"]);

            }
        }

        static void PBE_Tests()
        {
            byte[] password = UTF8Encoding.ASCII.GetBytes("password");
            byte[] salt = UTF8Encoding.ASCII.GetBytes("salt");

            byte[] output = Recipient.PBKF2(password, salt, 1, 20, new Sha1Digest());
            output = Recipient.PBKF2(password, salt, 2, 20, new Sha1Digest());

        }

        static void ProcessPassport(JSON control)
        {

        }

    }

#if false
    public enum JsonType
    {
        unknown = -1, map = 1, text = 2, array = 3, number = 4, boolean = 5
    }
#endif

#if false
    public class JSON
    {
        string source;
        public JsonType nodeType = JsonType.unknown;
        public Dictionary<string, JSON> map;
        public string text;
        public List<JSON> array;
        public int number;

        public JSON()
        {

        }

        public JSON(String text)
        {
            source = text;
            int used = Parse(0);
            if (used != text.Length) throw new Exception("Did not use entire string");
        }

        public JSON(byte[] rgb)
        {
            text = Message.base64urlencode(rgb);
            nodeType = JsonType.text;
        }

        public JSON(int i)
        {
            nodeType = JsonType.number;
            number = i;
        }

        public static JSON Parse(String text)
        {
            JSON json = new JSON();
            json.Parse(text, 0);
            return json;
        }

        public int Parse(String text, int offset)
        {
            source = text;
            return Parse(offset);
        }

        private int Parse(int offset)
        {
            int offsetStart = offset;



            offset += SkipWhiteSpace(offset);

            switch (source[offset]) {
            case '{':
                offset += ParseMap(offset);
                break;

            case '"':
                offset += ParseString(offset);
                break;

            case '[':
                offset += ParseArray(offset);
                break;

            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':
            case '8':
            case '9':
                offset += ParseNumber(offset);
                break;

            case 'f':
                offset += ParseWord(offset, "false");
                break;

            case 't':
                offset += ParseWord(offset, "true");
                break;

            default:

                throw new Exception("Invalid JSON string");
            }

            offset += SkipWhiteSpace(offset);

            return offset - offsetStart;
        }

        private int ParseArray(int offset)
        {
            int offsetStart = offset;

            nodeType = JsonType.array;
            array = new List<JSON>();

            if (source[offset] != '[') throw new Exception("Bad JSON array");
            offset += 1;
            offset += SkipWhiteSpace(offset);

            while (source[offset] != ']') {
                JSON value = new JSON();
                offset += value.Parse(source, offset);
                array.Add(value);
                offset += SkipWhiteSpace(offset);
                if (source[offset] == ',') {
                    offset += 1;
                    offset += SkipWhiteSpace(offset);
                }
                else if (source[offset] != ']') throw new Exception("Bad JSON array");
            }

            offset += 1;

            return offset - offsetStart;
        }

        private int ParseMap(int offset)
        {
            int offsetStart = offset;

            nodeType = JsonType.map;
            map = new Dictionary<string, JSON>();

            offset += SkipWhiteSpace(offset);

            //  Start of map
            if (source[offset] != '{') throw new Exception("Invalid Map");
            offset += 1;

            while (true) {
                offset += SkipWhiteSpace(offset);
                if (source[offset] == '}') break;

                JSON key = new JSON();
                offset += key.Parse(source, offset);
                if (key.nodeType != JsonType.text) throw new Exception("Invalid map");

                offset += SkipWhiteSpace(offset);

                if (source[offset] != ':') throw new Exception("Invalid Map");
                offset += 1;

                JSON value = new JSON();
                offset += value.Parse(source, offset);

                offset += SkipWhiteSpace(offset);

                map[key.text] = value;

                if (source[offset] != ',') break;
                offset += 1;

            }


            //  End of map
            if (source[offset] != '}') throw new Exception("Invalid Map");
            offset += 1;

            offset += SkipWhiteSpace(offset);

            return offset - offsetStart;
        }

        private int ParseNumber(int offsetStart)
        {
            int offset = offsetStart;

            int value = 0;

            offset += SkipWhiteSpace(offset);
            while (Char.IsDigit(source[offset])) {
                value = value * 10 + source[offset] - '0';
                offset += 1;
            }

            nodeType = JsonType.number;
            number = value;

            offset += SkipWhiteSpace(offset);
            return offset - offsetStart;
        }

        private int ParseWord(int offsetStart, string word)
        {
            int offset = offsetStart;

            for (int i = 0; i < word.Length; i++) {
                if (source[offset + i] != word[i]) throw new Exception("Invalid JSON matching " + word);
            }

            offset += word.Length + 1;
            offset += SkipWhiteSpace(offset);

            switch (word) {
            case "false": nodeType = JsonType.boolean; number = 0; break;
            case "true": nodeType = JsonType.boolean; number = -1; break;
            default: throw new Exception("ICE");
            }

            return offset - offsetStart;
        }

        private int ParseString(int offsetStart)
        {
            int offset = offsetStart;
            string strOut = "";
            Dictionary<char, char> escapee = new Dictionary<char, char>();
            escapee['"'] = '"';
            escapee['\\'] = '\\';
            escapee['/'] = '/';
            escapee['b'] = '\b';
            escapee['f'] = '\f';
            escapee['n'] = '\n';
            escapee['r'] = '\r';
            escapee['t'] = '\t';

            offset += SkipWhiteSpace(offset);

            if (source[offset] != '"') throw new Exception("Invalid Map");

            while (++offset < source.Length) {
                if (source[offset] == '"') {
                    offset += 1;
                    break;
                }

                if (source[offset] == '\\') {
                    offset += 1;
                    if (source[offset] == 'u') {
                        int uffff = 0;
                        int x;
                        for (int i = 0; i < 4; i++) {
                            if ('0' <= source[offset] && source[offset] <= '9') x = source[offset] - '0';
                            else if ('a' <= source[offset] && source[offset] <= 'f') x = source[offset] - 'a' + 10;
                            else if ('A' <= source[offset] && source[offset] <= 'F') x = source[offset] - 'A' + 10;
                            else throw new Exception("Invalid hex value");
                            uffff = uffff * 16 + x;
                        }
                        strOut += Convert.ToChar(uffff);
                    }
                    else if (escapee.ContainsKey(source[offset])) {
                        strOut += escapee[source[offset]];
                    }
                }
                else {
                    strOut += source[offset];
                }
            }

            nodeType = JsonType.text;
            text = strOut;

            return offset - offsetStart;
        }

        private int SkipWhiteSpace(int offsetStart)
        {
            int offset = offsetStart;

            while ((offset < source.Length) && Char.IsWhiteSpace(source[offset])) offset += 1;
            return offset - offsetStart;
        }

        public static JSON FromObject(Object obj)
        {
            if (obj.GetType() == typeof(JSON)) {
                return (JSON) obj;
            }
            else if (obj.GetType() == typeof(string)) {
                JSON objJson = new JSON();
                objJson.nodeType = JsonType.text;
                objJson.text = (string) obj;
                return objJson;
            }
            else {
                throw new Exception("did not change the type of the result");
            }
        }

        public void Add(Object obj)
        {
            if (nodeType == JsonType.unknown) {
                nodeType = JsonType.array;
                array = new List<JSON>();
            }
            else if (nodeType != JsonType.array) {
                throw new Exception("Can't change type of JSON node");
            }

            array.Add(FromObject(obj));
        }

        public void Add(string key, Object obj)
        {
            if (nodeType == JsonType.unknown) {
                nodeType = JsonType.map;
                map = new Dictionary<string, JSON>();
            }
            else if (nodeType != JsonType.map) {
                throw new Exception("Can't change type of JSON node");
            }

            map[key] = FromObject(obj);
        }

        public bool ContainsKey(string key)
        {
            return map.ContainsKey(key);
        }

        public void Remove(string key)
        {
            if (nodeType != JsonType.map) throw new Exception("Not a map");
            map.Remove(key);
        }

        public JSON this[string key]
        {
            get
            {
                if (nodeType == JsonType.map) {
                    return map[key];
                }
                throw new Exception("invalid index into json object");
            }
            set { if (nodeType == JsonType.unknown) { nodeType = JsonType.map; map = new Dictionary<string, JSON>(); } if (nodeType == JsonType.map) map[key] = value; else throw new Exception("Invlid index into json object"); }
        }

        public JSON this[int index]
        {
            get { if (nodeType == JsonType.array) return array[index]; throw new Exception("bad index not array"); }
        }

        public string AsString()
        {
            if (nodeType != JsonType.text) throw new Exception("Not a string");
            return text;
        }

        public int AsInteger()
        {
            if (nodeType != JsonType.number) throw new Exception("not an integer");
            return number;
        }

        public byte[] AsBytes()
        {
            if (nodeType != JsonType.text) throw new Exception("not a string");
            return Message.base64urldecode(text);
        }

        public int Count
        {
            get
            {
                if (nodeType == JsonType.array) return array.Count;
                if (nodeType == JsonType.map) return map.Count;
                return 0;
            }
        }
    }
#endif
}
