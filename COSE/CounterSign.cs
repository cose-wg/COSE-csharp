using System;
using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class CounterSignature : Signer
    {
        private Message m_msgToSign;
        private Signer m_signerToSign;


        public CounterSignature()
        {
            context = "CounterSignature";
        }

        public CounterSignature(OneKey key, CBORObject algorithm = null) : base(key, algorithm)
        {
            context = "CounterSignature";
        }

        public CounterSignature(byte[] rgBytes)
        {
            context = "CounterSignature";
            CBORObject cbor = CBORObject.DecodeFromBytes(rgBytes);

            ((Signer)this).DecodeFromCBORObject(cbor);
        }

        public CounterSignature(CBORObject obj)
        {
            context = "CounterSignature";
            ((Signer)this).DecodeFromCBORObject(obj);
        }

        public void SetObject(Message msg)
        {
            m_msgToSign = msg;
        }

        public void SetObject(Signer signer)
        {
            m_signerToSign = signer;
        }

        #region Decoders

        public new static CounterSignature DecodeFromCBORObject(CBORObject obj)
        {
            CounterSignature cs = new CounterSignature();
            ((Signer) cs).DecodeFromCBORObject(obj);
            return cs;
        }

        #endregion
        public new CBORObject EncodeToCBORObject()
        {
            CBORObject cborBodyAttributes = null;
            byte[] rgbBody = null;

            if (m_msgToSign != null) {
                if (m_msgToSign.GetType() == typeof(EncryptMessage)) {
                    EncryptMessage msg = (EncryptMessage)m_msgToSign;
                    msg.Encrypt();
                    CBORObject obj = msg.EncodeToCBORObject();
                    if (obj[1].Type != CBORType.ByteString) throw new Exception("Internal error");
                    if (obj[3].Type != CBORType.ByteString) throw new Exception("Internal error");
                    rgbBody = obj[3].GetByteString();
                    cborBodyAttributes = obj[1];
                }
            }
            else if (m_signerToSign != null) {
                CBORObject obj = m_signerToSign.EncodeToCBORObject();
            }


            return base.EncodeToCBORObject(cborBodyAttributes.GetByteString(), rgbBody);
        }
    }

    public class CounterSignature1 : Signer
    {
        private Message m_msgToSign;
        private Signer m_signerToSign;

        public CounterSignature1()
        {
            context = "CounterSignature0";
        }

        public CounterSignature1(OneKey key, CBORObject algorithm = null) : base(key, algorithm)
        {
            context = "CounterSignature0";
            if (UnprotectedMap.Count > 0) {
                UnprotectedMap = CBORObject.NewMap();
            }
        }

        public CounterSignature1(byte[] rgBytes)
        {
            context = "CounterSignature0";
            _rgbSignature = rgBytes;
            ProtectedBytes = new byte[0];
        }

        public void SetObject(Message msg)
        {
            m_msgToSign = msg;
        }

        public void SetObject(Signer signer)
        {
            m_signerToSign = signer;
        }

        public new void DecodeFromCBORObject(CBORObject cbor)
        {
            if (cbor.Type != CBORType.ByteString) throw new CoseException("Invalid format for CounterSignature0");
            _rgbSignature = cbor.GetByteString();
            ProtectedBytes = new byte[0];
        }

        public new CBORObject EncodeToCBORObject(byte[] bodyAttributes, byte[] body)
        {
            if (ProtectedMap.Count != 0 || UnprotectedMap.Count != 0) {
                throw new CoseException("Countsigner1 object cannot have protected or unprotected attributes");
            }

            CBORObject o = base.EncodeToCBORObject(bodyAttributes, body);

            return o[2];
        }

        public new CBORObject EncodeToCBORObject()
        {
            CBORObject cborBodyAttributes = null;
            byte[] rgbBody = null;

            if (m_msgToSign != null) {
                if (m_msgToSign.GetType() == typeof(EncryptMessage)) {
                    EncryptMessage msg = (EncryptMessage)m_msgToSign;
                    msg.Encrypt();
                    rgbBody = msg.GetEncryptedContent();
                }
                else if (m_msgToSign.GetType() == typeof(Encrypt0Message)) {
                    Encrypt0Message msg = (Encrypt0Message) m_msgToSign;
                    rgbBody = msg.GetEncryptedContent();
                    if (rgbBody == null) throw new CoseException("Need to encrypt message before countersignatures can be processed.");
                }
                cborBodyAttributes = m_msgToSign.ProtectedMap;
            }
            else if (m_signerToSign != null) {
                CBORObject obj = m_signerToSign.EncodeToCBORObject();
                cborBodyAttributes = m_signerToSign.ProtectedMap;
            }
            else {
                throw new CoseException("Internal state error - NYI");
            }


            CBORObject signed = base.EncodeToCBORObject(cborBodyAttributes.EncodeToBytes(), rgbBody);
            return signed[2];
        }
    }
}
