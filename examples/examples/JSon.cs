using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

namespace examples
{
#if USE_JOSE
        public enum JsonType
    {
        unknown = -1, map = 1, text = 2, array=3, number=4
    }

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

        private void Clear()
        {
            switch (nodeType) {
            case JsonType.text: text = null; break;
            case JsonType.number: number = 0; break;
            case JsonType.array: array = null; break;
            case JsonType.map: map = null; break;
            }

            nodeType = JsonType.unknown;
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

            case '0': case '1': case '2': case '3': case '4': case '5':
            case '6': case '7': case '8': case '9':
                offset += ParseNumber(offset);
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

        public CBORObject AsCbor()
        {
            CBORObject obj;

            switch (nodeType) {
            case JsonType.array:
                obj = CBORObject.NewArray();
                foreach (KeyValuePair<string, JSON> pair in map) {
                    obj.Add(pair.Key, pair.Value.AsCbor());
                }
                return obj;

            case JsonType.map:
                obj = CBORObject.NewMap();
                foreach (KeyValuePair<string, JSON> pair in map) {
                    obj.Add(pair.Key, pair.Value.AsCbor());
                }
                return obj;

            case JsonType.number:
                return CBORObject.FromObject(number);

            case JsonType.text:
                return CBORObject.FromObject(text);

            case JsonType.unknown:
            default:
                throw new Exception("Can deal with unknown JSON node type");
            }

       
        }

        public int Count()
        {
            if (nodeType == JsonType.array) return array.Count;
            if (nodeType == JsonType.map) return map.Count;
            return 1;
        }

        public string Set(string value)
        {
            Clear();
            nodeType = JsonType.text;
            text = value;

            return value;
        }

        public string Serialize(int depth=0)
        {
            string tmp = "";

            switch (nodeType) {
            case JsonType.text:
                return '"' + text.Replace("\n", "\\n") + "\"";

            case JsonType.number:
                return number.ToString();

            case JsonType.map:
                tmp = "{\n";
                foreach (KeyValuePair<string, JSON> pair in map) {
                    tmp += indent(depth+1) + '"' + pair.Key + "\": " + pair.Value.Serialize(depth+1) + ",\n";
                }
                tmp = tmp.Substring(0, tmp.Length-2) + "\n" + indent(depth) + "}";
                return tmp;

            case JsonType.array:
                tmp = "[\n";
                foreach (JSON value in array) {
                    tmp += indent(depth+1) + value.Serialize(depth+1) + ",\n";
                }
                tmp = tmp.Substring(0, tmp.Length - 2) + "\n" + indent(depth) + "]";
                return tmp;
            }
            return null;
        }

        private string indent(int depth)
        {
            string tmp = "";
            for (int i=0; i<depth; i++) tmp += "    ";
            return tmp;
        }
    }
#endif // USE_JOSE
}
