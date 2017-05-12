using System.Linq;

using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class Encrypt0Message : EncryptCommon
    {
        public Encrypt0Message() : base(true, true)
        {
            _context = "Encrypt0";
            m_tag = Tags.Encrypt0;
        }

        public Encrypt0Message(bool fEmitTag, bool fEmitContent = true) : base(fEmitTag, fEmitContent)
        {
            _context = "Encrypt0";
            m_tag = Tags.Encrypt0;
        }

        public virtual void DecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 3) throw new CoseException("Invalid Encrypt0 structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString)
            {
                if (obj[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else objProtected = CBORObject.DecodeFromBytes(obj[0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encrypt0 structure");
            }
            else
            {
                throw new CoseException("Invalid Encrypt0 structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) objUnprotected = obj[1];
            else throw new CoseException("Invalid Encrypt0 structure");

            // Cipher Text
            if (obj[2].Type == CBORType.ByteString) _rgbEncrypted = obj[2].GetByteString();
            else if (!obj[2].IsNull)
            {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encrypt0 structure");
            }
        }

        public override CBORObject Encode()
        {
            CBORObject obj;

            if (_rgbEncrypted == null) throw new CoseException("Must call Encrypt first");

            if (m_counterSignerList.Count() != 0) {
                if (m_counterSignerList.Count() == 1) {
                    AddAttribute(HeaderKeys.CounterSignature, m_counterSignerList[0].EncodeToCBORObject(_rgbProtected, _rgbEncrypted), UNPROTECTED);
                }
                else {
                    foreach (CounterSignature sig in m_counterSignerList) {
                        sig.EncodeToCBORObject(_rgbProtected, _rgbEncrypted);
                    }
                }
            }
            obj = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                obj.Add(objProtected.EncodeToBytes());
            }
            else obj.Add(CBORObject.FromObject(new byte[0]));

            obj.Add(objUnprotected); // Add unprotected attributes

            if (m_emitContent) obj.Add(_rgbEncrypted);      // Add ciphertext
            else obj.Add(CBORObject.Null);

            return obj;
        }

        public byte[] Decrypt(byte[] rgbKey)
        {
            DecryptWithKey(rgbKey);
            return rgbContent;
        }

        public void Encrypt(byte[] rgbKey)
        {
            EncryptWithKey(rgbKey);
        }
    }
}
