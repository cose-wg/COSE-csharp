﻿using System.Linq;

using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class Encrypt0Message : EncryptCommon
    {
        /// <summary>
        /// Implement the COSE_Encrypt0 protocol element from RFC 8215.
        /// This will emit the tag and the content
        /// </summary>
        public Encrypt0Message() : base(true, true, "Encrypt0")
        {
            m_tag = Tags.Encrypt0;
        }

        /// <summary>
        /// Implement the COSE_Encrypt0 protocol element from RFC 8215.
        /// </summary>
        /// <param name="fEmitTag">emit leading tag</param>
        /// <param name="fEmitContent">emit message content</param>
        public Encrypt0Message(bool fEmitTag, bool fEmitContent = true) : base(fEmitTag, fEmitContent, "Encrypt0")
        {
            m_tag = Tags.Encrypt0;
        }

#region Decoders
        /// <summary>
        /// Decode an Encrypt0 Message from bytes
        /// </summary>
        /// <param name="rgb">encoded message</param>
        /// <returns>decoded Encrypt0Message object</returns>
        public static Encrypt0Message DecodeFromBytes(byte[] rgb)
        {
            return (Encrypt0Message) Message.DecodeFromBytes(rgb, Tags.Encrypt0);
        }

        /// <summary>
        /// Given a CBOR tree, try and parse the tree into an Encrypt0 item.
        /// </summary>
        /// <param name="obj">CBOR Object to decode</param>
        /// <returns>Decoded Encrypt0Message</returns>
        public static Encrypt0Message DecodeFromCBOR(CBORObject obj)
        {
            return (Encrypt0Message)Message.DecodeFromCBOR(obj, Tags.Encrypt0);
        }

        protected override void InternalDecodeFromCBORObject(CBORObject cbor)
        {
            if (cbor.Count != 3) throw new CoseException("Invalid Encrypt0 structure");

            //  Protected values.
            if (cbor[0].Type == CBORType.ByteString)
            {
                if (cbor[0].GetByteString().Length == 0) ProtectedMap = CBORObject.NewMap();
                else ProtectedMap = CBORObject.DecodeFromBytes(cbor[0].GetByteString());
                if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid Encrypt0 structure");
                ProtectedBytes = cbor[0].GetByteString();
            }
            else
            {
                throw new CoseException("Invalid Encrypt0 structure");
            }

            //  Unprotected attributes
            if (cbor[1].Type == CBORType.Map) UnprotectedMap = cbor[1];
            else throw new CoseException("Invalid Encrypt0 structure");

            // Cipher Text
            if (cbor[2].Type == CBORType.ByteString) RgbEncrypted = cbor[2].GetByteString();
            else if (!cbor[2].IsNull)
            {               // Detached content - will need to get externally
                throw new CoseException("Invalid Encrypt0 structure");
            }
        }
#endregion

        /// <summary>
        /// Encode the COSE Encrypt0 item to a CBOR tree.
        /// <see cref="Encrypt"/> must be done prior to calling this function.
        /// </summary>
        /// <returns></returns>
        public override CBORObject Encode()
        {
            CBORObject cbor;

            if (RgbEncrypted == null) throw new CoseException("Must call Encrypt first");

            ProcessCounterSignatures();

            cbor = CBORObject.NewArray();

            if (ProtectedMap.Count > 0) {
                cbor.Add(ProtectedMap.EncodeToBytes());
            }
            else cbor.Add(CBORObject.FromObject(new byte[0]));

            cbor.Add(UnprotectedMap); // Add unprotected attributes

            if (m_emitContent) cbor.Add(RgbEncrypted);      // Add ciphertext
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

            ProcessCounterSignatures();
        }
    }
}
