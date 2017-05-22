using System.Linq;

using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class Encrypt0Message : EncryptCommon
    {
        /// <summary>
        /// Implement the COSE_Encrypt0 protocol element from RFC 8215.
        /// This will emit the tag and the content
        /// </summary>
        public Encrypt0Message() : base(true, true)
        {
            _context = "Encrypt0";
            m_tag = Tags.Encrypt0;
        }

        /// <summary>
        /// Implement the COSE_Encrypt0 protocol element from RFC 8215.
        /// </summary>
        /// <param name="fEmitTag">emit leading tag</param>
        /// <param name="fEmitContent">emit message content</param>
        public Encrypt0Message(bool fEmitTag, bool fEmitContent = true) : base(fEmitTag, fEmitContent)
        {
            _context = "Encrypt0";
            m_tag = Tags.Encrypt0;
        }

        /// <summary>
        /// Given a CBOR tree, try and parse the tree into an Encrypt0 item.
        /// </summary>
        /// <param name="cbor"></param>
        public virtual void DecodeFromCBORObject(CBORObject cbor)
        {
            if (cbor.Count != 3) throw new CoseException("Invalid Encrypt0 structure");

            //  Protected values.
            if (cbor[0].Type == CBORType.ByteString)
            {
                if (cbor[0].GetByteString().Length == 0) objProtected = CBORObject.NewMap();
                else objProtected = CBORObject.DecodeFromBytes(cbor[0].GetByteString());
                if (objProtected.Type != CBORType.Map) throw new CoseException("Invalid Encrypt0 structure");
            }
            else
            {
                throw new CoseException("Invalid Encrypt0 structure");
            }

            //  Unprotected attributes
            if (cbor[1].Type == CBORType.Map) objUnprotected = cbor[1];
            else throw new CoseException("Invalid Encrypt0 structure");

            // Cipher Text
            if (cbor[2].Type == CBORType.ByteString) _rgbEncrypted = cbor[2].GetByteString();
            else if (!cbor[2].IsNull)
            {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encrypt0 structure");
            }
        }

        /// <summary>
        /// Encode the COSE Encrypt0 item to a CBOR tree.
        /// <see cref="Encrypt"/> must be done prior to calling this function.
        /// </summary>
        /// <returns></returns>
        public override CBORObject Encode()
        {
            CBORObject cbor;

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
            cbor = CBORObject.NewArray();

            if (objProtected.Count > 0) {
                cbor.Add(objProtected.EncodeToBytes());
            }
            else cbor.Add(CBORObject.FromObject(new byte[0]));

            cbor.Add(objUnprotected); // Add unprotected attributes

            if (m_emitContent) cbor.Add(_rgbEncrypted);      // Add ciphertext
            else cbor.Add(CBORObject.Null);

            return cbor;
        }

        /// <summary>
        /// Attempt to decrypt the message.
        /// </summary>
        /// <param name="rgbKey">key to be used for decryption</param>
        /// <returns>decrypted content</returns>
        public byte[] Decrypt(byte[] rgbKey)
        {
            DecryptWithKey(rgbKey);
            return rgbContent;
        }

        /// <summary>
        /// Encrypt the message with the provided key
        /// </summary>
        /// <param name="rgbKey">key for encryption</param>
        public void Encrypt(byte[] rgbKey)
        {
            EncryptWithKey(rgbKey);
        }
    }
}
