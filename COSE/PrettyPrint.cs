using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;

namespace COSE
{
    public class PrettyPrint
    {
        public string PrintCBOR(byte[] rgb)
        {
            CBORObject obj = CBORObject.DecodeFromBytes(rgb);
            return _PrintCBOR(obj, 0);
        }
        private string _PrintCBOR(CBORObject obj, int iLevel)
        {
            string strOut = "";
            string strLine;
            string pad = ((String)"                    ").Substring(0, iLevel);

            switch (obj.Type) {
            case CBORType.Array:
                strOut = "[\n";
                for (int i = 0; i < obj.Count; i++) {
                    strOut += pad + " " + _PrintCBOR(obj[i], iLevel+1) + ",\n";
                }
                strOut += pad + "]";
                break;

            case CBORType.Map:
                strOut = "{\n";
                foreach (CBORObject key in obj.Keys) { 
                    strOut += pad + " " + _PrintCBOR(key, 0) + " : " + _PrintCBOR(obj[key], iLevel+1) + ",\n";
                }
                strOut += pad + "}";
                break;

            case CBORType.ByteString:
                strLine = pad + "h'";
                byte[] rgb = obj.GetByteString();
                    byte[] rgb2 = new byte[1];
                foreach (byte b in rgb) {
                    if (strLine.Length > 66) {
                        if (strOut == "") {
                            strOut = strLine.Substring(iLevel) + "\n";
                        }
                        else strOut += strLine + "\n";
                        strLine = pad + "  ";
                    }
                    rgb2[0] = b;
                    strLine += BitConverter.ToString(rgb2);
                }
                strOut += strLine;
                strOut += "'";
                break;

            case CBORType.Number:
                strOut = obj.AsInt32().ToString();
                break;

            case CBORType.SimpleValue:
                if (obj.IsNull) return "null";
                return obj.Type.ToString();

            case CBORType.TextString:
                strOut = "\"" + obj.AsString() + "\"";
                break;
                
            default:
                strOut = obj.Type.ToString();
                break;
            }

            return strOut;
        }
    }
}
