using System;
using System.Collections.Generic;
using System.Linq;

using PeterO.Cbor;

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace Com.AugustCellars.COSE
{
    public class SignMessage : Message
    {
        List<Signer> signerList = new List<Signer>();

        public SignMessage(bool fEmitTag = true, bool fEmitContent = true) : base(fEmitTag, fEmitContent)
        {
            m_tag = Tags.Sign;
        }

        public List<Signer> SignerList { get { return signerList; } }

        public void AddSigner(Signer sig)
        {
            signerList.Add(sig);
        }

        public byte[] BEncodeToBytes()
        {
            CBORObject obj2 = BEncodeToCBORObject();

            return obj2.EncodeToBytes();
        }

        public CBORObject BEncodeToCBORObject()
        {
            CBORObject objX = EncodeToCBORObject();
            CBORObject obj = CBORObject.NewMap();

            if (objX[2] != null) obj[CBORObject.FromObject(1)] = objX[2];
            if (objX[3] != null) {
                CBORObject obj3 = CBORObject.NewArray();
                obj[CBORObject.FromObject(2)] = obj3;
                for (int i = 0; i < objX[3].Count; i++) {
                    CBORObject obj2 = CBORObject.NewMap();
                    obj3.Add(obj2);
                    obj2[CBORObject.FromObject(3)] = objX[3][i][2];
                    obj2[CBORObject.FromObject(4)] = objX[3][i][1];
                    if (objX[3][i][0] != null) {
                        obj2[CBORObject.FromObject(5)] = objX[3][i][0];
                    }
                }
            }
            return obj;
        }

#region Decoders
        public static SignMessage DecodeFromCBOR(CBORObject obj)
        {
            return (SignMessage) Message.DecodeFromCBOR(obj, Tags.Sign);
        }
        
        protected override void InternalDecodeFromCBORObject(CBORObject obj)
        {
            if (obj.Count != 4) throw new CoseException("Invalid SignMessage structure");

            //  Protected values.
            if (obj[0].Type == CBORType.ByteString) {
                ProtectedBytes = obj[0].GetByteString();
                if (ProtectedBytes.Length == 0) ProtectedMap = CBORObject.NewMap();
                else {
                    ProtectedMap = CBORObject.DecodeFromBytes(ProtectedBytes);
                    if (ProtectedMap.Type != CBORType.Map) throw new CoseException("Invalid SignMessage structure");
                    if (ProtectedMap.Count == 0) ProtectedBytes = new byte[0];
                }
            }
            else {
                throw new CoseException("Invalid SignMessage structure");
            }

            //  Unprotected attributes
            if (obj[1].Type == CBORType.Map) UnprotectedMap = obj[1];
            else throw new CoseException("Invalid SignMessage structure");

            // Plain Text
            if (obj[2].Type == CBORType.ByteString) rgbContent = obj[2].GetByteString();
            else if (!obj[2].IsNull) {               // Detached content - will need to get externally
                throw new CoseException("Invalid SignMessage structure");
            }

            // Signers
            if (obj[3].Type != CBORType.Array) throw new CoseException("Invalid SignMessage structure");
            // An array of signers to be processed
            for (int i = 0; i < obj[3].Count; i++) {
                Signer recip = new Signer();
                recip.DecodeFromCBORObject(obj[3][i]);
                signerList.Add(recip);
            }

        }
#endregion

        public override CBORObject Encode()
        {
            CBORObject obj;
            byte[] rgbProtected;

            obj = CBORObject.NewArray();

            if ((ProtectedMap != null) && (ProtectedMap.Count > 0)) {
                rgbProtected = ProtectedMap.EncodeToBytes();
                obj.Add(rgbProtected);
            }
            else {
                rgbProtected = new byte[0];
                obj.Add(rgbProtected);
            }

            if (CounterSignerList.Count() != 0) {
                if (CounterSignerList.Count() == 1) {
                    AddAttribute(HeaderKeys.CounterSignature, CounterSignerList[0].EncodeToCBORObject(rgbProtected, rgbContent), UNPROTECTED);
                }
                else {
                    foreach (CounterSignature sig in CounterSignerList) {
                        sig.EncodeToCBORObject(rgbProtected, rgbContent);
                    }
                }
            }

            if ((UnprotectedMap == null) || (UnprotectedMap.Count == 0)) obj.Add(CBORObject.NewMap());
            else obj.Add(UnprotectedMap); // Add unprotected attributes

            obj.Add(rgbContent);

            if ((signerList.Count == 1) && !m_forceArray) {
                CBORObject recipient = signerList[0].EncodeToCBORObject(obj[0].EncodeToBytes(), rgbContent);

                for (int i = 0; i < recipient.Count; i++) {
                    obj.Add(recipient[i]);
                }
            }
            else if (signerList.Count > 0) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in signerList) {
                    signers.Add(key.EncodeToCBORObject(rgbProtected, rgbContent));
                }
                obj.Add(signers);
            }
            else {
                obj.Add(null);      // No recipients - set to null
            }
            return obj;
        }

        public bool Validate(Signer signer)
        {
            foreach (Signer x in signerList) {
                if (x == signer) {
                    return signer.Validate(rgbContent, ProtectedBytes);
                }
            }

            throw new Exception("Signer is not for this message");
        }

    }


}
