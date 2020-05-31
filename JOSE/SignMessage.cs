using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using PeterO.Cbor;


namespace Com.AugustCellars.JOSE
{
    public class SignMessage : Message
    {
        public List<Signer> SignerList { get; } = new List<Signer>();

        public SignMessage()
        {

        }

        public SignMessage(CBORObject json)
        {
            InternalDecodeFromJSON(json);
        }

        /// <inheritdoc />
        protected override void InternalDecodeFromJSON(CBORObject json)
        {
            //  Parse out the message from the JSON

            if (json.ContainsKey("signatures")) {
                if (json.ContainsKey("signature")) {
                    throw new JoseException("Cannot have both 'signatures' and 'signature' present.");
                }
                CBORObject signers = json["signatures"];
                if (signers.Type != CBORType.Array || signers.Count == 0) {
                    throw new JoseException("field 'signatures' must be a non-empty array.");
                }
                for (int i = 0; i < signers.Count; i++) {
                    Signer signer = new Signer(signers[i]);
                    SignerList.Add(signer);
                }
            }
            else if (json.ContainsKey("signature")) {
                Signer signer = new Signer(json);
                SignerList.Add(signer);
            }
            else {
                throw new JoseException("field 'signatures' or 'signature' must be present.");
            }

            if (json.ContainsKey("payload")) {
                CBORObject b64 = SignerList[0].FindAttribute(CBORObject.FromObject("b64"), PROTECTED);
                if (b64 != null) {
                    if (b64.Type != CBORType.Boolean) throw new Exception("Invalid message");
                    if (b64.AsBoolean()) {
                        payloadB64 = Encoding.UTF8.GetBytes(json["payload"].AsString());
                        payload = base64urldecode(json["payload"].AsString());
                    }
                    else {
                        payload = Encoding.UTF8.GetBytes(json["payload"].AsString());
                        payloadB64 = payload;
                    }
                }
                else {
                    payloadB64 = Encoding.UTF8.GetBytes(json["payload"].AsString());
                    payload = base64urldecode(json["payload"].AsString());
                }
            }
            else {
                throw new JoseException("field 'payload' must be present.");
            }
        }

        public void AddSigner(Signer sig)
        {
            SignerList.Add(sig);
        }


        /// <inheritdoc />
        protected override string InternalEncodeCompressed()
        {
            CBORObject objBody;
            CBORObject objSigners = null;

            if (SignerList.Count != 1) throw new JoseException("Compact mode not supported if more than one signer");
            if (UnprotectedMap.Count > 0) throw new JoseException("Compact mode not supported if unprotected attributes exist");

            objBody = EncodeToJSON();

            //  Base64 encoding says kill some messages
            

            if (objBody.ContainsKey("signatures")) objSigners = objBody["signatures"][0];

            string str = "";
            if (objSigners != null && objSigners.ContainsKey("protected")) str += objSigners["protected"].AsString();
            str += ".";
            if (objBody.ContainsKey("payload")) {
                if (objBody["payload"].AsString().Contains('.')) throw new Exception("Message cannot contain a period character");
                str += objBody["payload"].AsString();
            }
            str += ".";
            if (objSigners != null && objSigners.ContainsKey("signature")) str += objSigners["signature"].AsString();

            return str;
        }

        /// <inheritdoc />
        protected override CBORObject InternalEncodeToJSON(bool fCompact)
        {
            CBORObject obj = CBORObject.NewMap();
            
            if (UnprotectedMap.Count > 0) obj.Add("unprotected", UnprotectedMap); // Add unprotected attributes

            //  Look at the world of base64 encoded bodies.
            //   If any signer has the b64 false, then all of them need to.
            //   Then change our body if needed

            int b64Found = 0;
            bool b64Value = true;

            foreach( Signer key in SignerList) {
                CBORObject attr = key.FindAttribute(CBORObject.FromObject( "b64"), PROTECTED);
                if (attr != null) {
                    if (b64Found == 0) b64Value = attr.AsBoolean();
                    else if (b64Value != attr.AsBoolean()) {
                        throw new JoseException("Not all signers using the same value for b64");
                    }
                    b64Found += 1;
                }
            }

            if (b64Value) {
                obj.Add("payload", base64urlencode(payload));
            }
            else {
                if (b64Found != SignerList.Count) throw new JoseException("Not all signers using the same value for b64");
                obj.Add("payload", Encoding.UTF8.GetString(payload));
            }

            if (SignerList.Count > 0) {
                CBORObject signers = CBORObject.NewArray();

                foreach (Signer key in SignerList) {
                    signers.Add(key.EncodeToJSON(payload));
                }

                if (fCompact) {
                    if (SignerList.Count > 1) {
                        throw new JoseException("Compact format must be for single signer");
                    }

                    if (signers[0].ContainsKey("protected")) {
                        obj.Add("protected", signers[0]["protected"]);
                    }
                    obj.Add("signature", signers[0]["signature"]);
                }
                else {
                    obj.Add("signatures", signers);
                }

            }
            else {
                throw new JoseException("Must have some signers");
            }

            return obj;
        }


        public bool Validate(Signer signerToValidate)
        {
            if (signerToValidate == null) {
                foreach (Signer signer in SignerList) {
                    try {
                        signer.Verify(this);
                        return true;
                    }
                    catch (JoseException) {
                    }
                }

                return false;
            }

            foreach (Signer signer in SignerList) {
                if (signer == signerToValidate) {
                    try {
                        signer.Verify(this);
                        return true;
                    }
                    catch {
                        return false;
                    }
                }
            }

            throw new JoseException("Signer not in list of signers.");
        }
    }

}
