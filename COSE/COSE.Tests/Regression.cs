using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE.Tests
{

    // @RunWith(Parameterized.class)
    public class RegressionTest
    {
        //@Parameters(name = "{index}: {0})")
#if false
        public static Collection<Object> data()
        {
            return Arrays.asList(new Object[] {
            "Examples/aes-ccm-examples",
            "Examples/aes-gcm-examples",
            "Examples/aes-wrap-examples",
            "Examples/cbc-mac-examples",
            "Examples/ecdh-direct-examples",
            "Examples/ecdh-wrap-examples",
            "Examples/ecdsa-examples",
            "Examples/encrypted-tests",
            "Examples/enveloped-tests",
            "Examples/hkdf-hmac-sha-examples",
            "Examples/hmac-examples",
            "Examples/mac-tests",
            "Examples/mac0-tests",
            "Examples/sign-tests",
            "Examples/sign1-tests",
            "Examples/spec-examples",
           });
        }

        @Parameter // first data value (0) is default
#endif
        public /* NOT private */ String directoryName = "../Regressions";

        public int CFails = 0;

        [Test]
        public void ProcessDirectory()
        {
            CFails = 0;

            DirectoryInfo directory;
            try {
                directory = new DirectoryInfo(directoryName);
                if (!directory.Exists) {
                    directory = new DirectoryInfo("C:\\Projects\\cose\\Examples");
                }
            }
            catch (Exception) {
                directory = new DirectoryInfo(Path.Combine("C:\\Projects\\cose", directoryName));
            }

            foreach (var di in directory.EnumerateDirectories()) {
                if ((!di.Attributes.HasFlag(FileAttributes.Hidden)) &&
                    (di.FullName.Substring(di.FullName.Length-4) != "\\new")) {
#if !CHACHA20
                    if (di.Name == "chacha-poly-examples") continue;
#endif
                    if (di.Name == "X25519-tests") continue;
                    ProcessDirectory(Path.Combine(directory.FullName, di.Name));
                }
            }

            foreach (var fi in directory.EnumerateFiles()) {
                if (fi.Extension == ".json") {
                    if (fi.Name == "Appendix_B.json") continue;
                    ProcessFile(fi.FullName);
                }
            }
            Assert.That(CFails, Is.EqualTo(0));
        }

        public void ProcessDirectory(string dirName)
        {
            CFails = 0;

            Console.WriteLine("Test Directory " + dirName);
            DirectoryInfo directory;
            directory = new DirectoryInfo(dirName);
  
            foreach (var di in directory.EnumerateDirectories()) {
                if ((!di.Attributes.HasFlag(FileAttributes.Hidden)) &&
                    (di.FullName.Substring(di.FullName.Length - 4) != "\\new")) {
#if !CHACHA20
                    if (di.Name == "chacha-poly-examples") continue;
#endif
                    if (di.Name == "X25519-tests") continue;
                    ProcessDirectory(Path.Combine(directory.FullName, di.Name));
                }
            }

            foreach (var fi in directory.EnumerateFiles()) {
                if (fi.Extension == ".json") {
                    if (fi.Name == "Appendix_B.json") continue;
                    ProcessFile(fi.FullName);
                }
            }
            Assert.That(CFails, Is.EqualTo(0));
        }

        public void ProcessFile(String test)
        {
            try {
                int fails = CFails;
                StreamReader file  = File.OpenText(test);
                string str = file.ReadToEnd();
                file.Close();
                CBORObject foo = CBORObject.FromJSONString(str);

                int x = ProcessJSON(foo);
                if (fails != CFails) {
                    Console.Write("Check: " + test);
                    Console.Write("... FAIL\n");
                }
            }
            catch (Exception e) {
                Console.Write("Check: " + test);
                Console.Write("... FAIL\nException " + e + "\n");
                CFails++;
            }
        }

        public int ProcessJSON(CBORObject control)
        {
            CBORObject input = control["input"];
            if (input.ContainsKey("mac0")) {
                VerifyMac0Test(control);
                BuildMac0Test(control);
            }
            else if (input.ContainsKey("mac")) {
                VerifyMacTest(control);
                BuildMacTest(control);
            }
            else if (input.ContainsKey("encrypted")) {
                VerifyEncryptTest(control);
                BuildEncryptTest(control);
            }
            else if (input.ContainsKey("enveloped")) {
                VerifyEnvelopedTest(control);
                BuildEnvelopedTest(control);
            }
            else if (input.ContainsKey("sign")) {
                ValidateSigned(control);
                BuildSignedMessage(control);
            }
            else if (input.ContainsKey("sign0")) {
                ValidateSign0(control);
                BuildSign0Message(control);
            }
            else return 1;
            return 0;
        }

        public void BuildEncryptTest(CBORObject cnControl)
        {
            CBORObject cnFail = cnControl[ "fail"];
            if ((cnFail != null) && cnFail.AsBoolean()) return;

            CBORObject cnInput = cnControl[ "input"];
            CBORObject cnEncrypt = cnInput[ "encrypted"];

            Encrypt0Message msg = new Encrypt0Message();

            msg.SetContent(GetContent(cnInput));


            SetSendingAttributes(msg, cnEncrypt, true);

            CBORObject cnRecipients = cnEncrypt[ "recipients"];
            cnRecipients = cnRecipients[ 0];

            OneKey cnKey = BuildKey(cnRecipients[ "key"], true);

            CBORObject kk = cnKey[ CBORObject.FromObject(-1)];

            msg.Encrypt(kk.GetByteString());

            byte[] rgb = msg.EncodeToBytes();


            _VerifyEncrypt(cnControl, rgb);
        }

        public void VerifyEncryptTest(CBORObject control)
        {
            String strExample = control[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);
            _VerifyEncrypt(control, rgb);
        }

        public void _VerifyEncrypt(CBORObject control, byte[] rgbData)
        {
            CBORObject cnInput = control[ "input"];
            // Boolean fFail = false;
            Boolean fFailBody = false;

            CBORObject cnFail = control[ "fail"];
            if ((cnFail != null) && (cnFail.Type == CBORType.Boolean) &&
                  cnFail.AsBoolean()) {
                fFailBody = true;
            }

            try {
                Message msg = Message.DecodeFromBytes(rgbData, Tags.Encrypt0);
                Encrypt0Message enc0 = (Encrypt0Message)msg;

                CBORObject cnEncrypt = cnInput[ "encrypted"];
                SetReceivingAttributes(msg, cnEncrypt);

                CBORObject cnRecipients = cnEncrypt[ "recipients"];
                cnRecipients = cnRecipients[ 0];

                OneKey cnKey = BuildKey(cnRecipients[ "key"], true);

                CBORObject kk = cnKey[ CBORObject.FromObject(-1)];

                cnFail = cnRecipients[ "fail"];

                try {
                    byte[] rgbContent = enc0.Decrypt(kk.GetByteString());
                    if ((cnFail != null) && !cnFail.AsBoolean()) CFails++;
                    byte[] oldContent = GetContent(cnInput);
                    Assert.That(oldContent, Is.EqualTo(rgbContent));
                }
                catch (Exception) {
                    if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) CFails++;
                }
            }
            catch (Exception) {
                if (!fFailBody) CFails++;
            }
        }

        void BuildMacTest(CBORObject cnControl)
        {
            int iRecipient;

            //
            //  We don't run this for all control sequences - skip those marked fail.
            //

            if (HasFailMarker(cnControl)) return;

            MACMessage hEncObj = new MACMessage();

            CBORObject cnInputs = cnControl[ "input"];
            CBORObject cnEnveloped = cnInputs[ "mac"];

            hEncObj.SetContent(GetContent(cnInputs));


            SetSendingAttributes(hEncObj, cnEnveloped, true);

            CBORObject cnRecipients = cnEnveloped[ "recipients"];

            for (iRecipient = 0; iRecipient < cnRecipients.Count; iRecipient++) {
                Recipient hRecip = BuildRecipient(cnRecipients[ iRecipient]);

                hEncObj.AddRecipient(hRecip);
            }

            hEncObj.Compute();

            byte[] rgb = hEncObj.EncodeToBytes();


            _VerifyMac(cnControl, rgb);

            return;
        }

        public void BuildMac0Test(CBORObject cnControl)
        {
            CBORObject cnFail = cnControl[ "fail"];
            if ((cnFail != null) && cnFail.AsBoolean()) return;

            CBORObject cnInput = cnControl[ "input"];
            CBORObject cnEncrypt = cnInput[ "mac0"];

            MAC0Message msg = new MAC0Message();

            msg.SetContent(GetContent(cnInput));


            SetSendingAttributes(msg, cnEncrypt, true);

            CBORObject cnRecipients = cnEncrypt[ "recipients"];
            cnRecipients = cnRecipients[ 0];

            OneKey cnKey = BuildKey(cnRecipients[ "key"], true);

            CBORObject kk = cnKey[ CBORObject.FromObject(-1)];

            msg.Compute(kk.GetByteString());

            byte[] rgb = msg.EncodeToBytes();


            _VerifyMac0(cnControl, rgb);
        }

        public void VerifyMac0Test(CBORObject control)
        {
            String strExample = control[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);
            _VerifyMac0(control, rgb);
        }
        public void _VerifyMac0(CBORObject control, byte[] rgbData)
        {
            CBORObject cnInput = control[ "input"];
            // Boolean fFail = false;
            Boolean fFailBody = false;

            try {
                CBORObject pFail = control[ "fail"];
                if ((pFail != null) && (pFail.Type == CBORType.Boolean) &&
                      pFail.AsBoolean()) {
                    fFailBody = true;
                }

                Message msg = Message.DecodeFromBytes(rgbData, Tags.MAC0);
                MAC0Message mac0 = (MAC0Message)msg;

                CBORObject cnMac = cnInput[ "mac0"];
                SetReceivingAttributes(msg, cnMac);

                CBORObject cnRecipients = cnMac[ "recipients"];
                cnRecipients = cnRecipients[ 0];

                OneKey cnKey = BuildKey(cnRecipients[ "key"], true);

                CBORObject kk = cnKey[ CBORObject.FromObject(-1)];

                pFail = cnRecipients[ "fail"];

                Boolean f = mac0.Validate(kk.GetByteString());

                if (f) {
                    if ((pFail != null) && pFail.AsBoolean()) CFails++;
                }
                else {
                    if ((pFail != null) && !pFail.AsBoolean()) CFails++;
                }

            }
            catch (Exception) {
                if (!fFailBody) CFails++;
            }
        }

        public void VerifyMacTest(CBORObject control)
        {
            String strExample = control[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);
            _VerifyMac(control, rgb);
        }

        public void _VerifyMac(CBORObject control, byte[] rgbData)
        {
            CBORObject cnInput = control[ "input"];
            Boolean fFail = false;
            Boolean fFailBody = false;

            try {
                Message msg = null;
                MACMessage mac = null;
                fFailBody = HasFailMarker(control);

                try {
                    msg = Message.DecodeFromBytes(rgbData, Tags.MAC);
                    mac = (MACMessage)msg;
                }
                catch (CoseException e) {
                    if (e.Message.StartsWith("Passed in tag does not match actual tag") && fFailBody) return;
                    CFails++;
                    return;
                }

                CBORObject cnMac = cnInput[ "mac"];
                SetReceivingAttributes(msg, cnMac);

                CBORObject cnRecipients = cnMac[ "recipients"];
                cnRecipients = cnRecipients[ 0];

                OneKey cnKey = BuildKey(cnRecipients[ "key"], false);
                Recipient recipient = mac.RecipientList[0];
                recipient.SetKey(cnKey);

                CBORObject cnStatic = cnRecipients[ "sender_key"];
                if (cnStatic != null) {
                    if (recipient.FindAttribute(HeaderKeys.ECDH_SPK) == null) {
                        recipient.AddAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attributes.DO_NOT_SEND);
                    }
                }

                fFail = HasFailMarker(cnRecipients);
                try {
                    Boolean f = mac.Validate(recipient);
                    if (f && (fFail || fFailBody)) CFails++;
                    else if (!f && !(fFail || fFailBody)) CFails++;
                }
                catch (Exception) {
                    if (fFail || fFailBody) return;
                    CFails++;
                    return;
                }
            }
            catch (Exception) {
                CFails++;
            }
        }

        Boolean DecryptMessage(byte[] rgbEncoded, Boolean fFailBody, CBORObject cnEnveloped, CBORObject cnRecipient1, int iRecipient1, CBORObject cnRecipient2, int iRecipient2)
        {
            EncryptMessage hEnc;
            Recipient hRecip;
            Recipient hRecip1;
            Recipient hRecip2;
            Boolean fRet = false;
            OneKey cnkey;
            Message msg;

            try {
                try {
                    msg = Message.DecodeFromBytes(rgbEncoded, Tags.Encrypt);
                }
                catch (CoseException e) {
                    if (fFailBody) return true;
                    throw e;
                }

                hEnc = (EncryptMessage)msg;

                //  Set enveloped attributes
                SetReceivingAttributes(hEnc, cnEnveloped);

                //  Set attibutes on base recipient
                hRecip1 = hEnc.RecipientList[iRecipient1];
                SetReceivingAttributes(hRecip1, cnRecipient1);

                if (cnRecipient2 != null) {
                    cnkey = BuildKey(cnRecipient2[ "key"], false);

                    hRecip2 = hRecip1.RecipientList[iRecipient2];

                    //  Set attributes on the recipients we are using.
                    SetReceivingAttributes(hRecip2, cnRecipient2);
                    hRecip2.SetKey(cnkey);

                    CBORObject cnStatic = cnRecipient2[ "sender_key"];
                    if (cnStatic != null) {
                        if (hRecip2.FindAttribute(HeaderKeys.ECDH_SPK) == null) {
                            hRecip2.AddAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attributes.DO_NOT_SEND);
                        }
                    }

                    hRecip = hRecip2;
                }
                else {
                    cnkey = BuildKey(cnRecipient1[ "key"], false);
                    hRecip1.SetKey(cnkey);

                    CBORObject cnStatic = cnRecipient1[ "sender_key"];
                    if (cnStatic != null) {
                        if (hRecip1.FindAttribute(HeaderKeys.ECDH_SPK) == null) {
                            hRecip1.AddAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnStatic, true).AsCBOR(), Attributes.DO_NOT_SEND);
                        }
                    }

                    hRecip = hRecip1;
                }


                if (!fFailBody) {
                    fFailBody |= HasFailMarker(cnRecipient1);
                    if (cnRecipient2 != null) fFailBody |= HasFailMarker(cnRecipient2);
                }

                try {
                    byte[] rgbOut = hEnc.Decrypt(hRecip);
                    if (fFailBody) fRet = false;
                    else fRet = true;
                }
                catch (Exception) {
                    if (!fFailBody) fRet = false;
                    else fRet = true;
                }
            }
            catch (Exception) {
                fRet = false;
            }

            return fRet;
        }

        int _ValidateEnveloped(CBORObject cnControl, byte[] rgbEncoded)
        {
            CBORObject cnInput = cnControl["input"];
            CBORObject cnEnveloped;
            CBORObject cnRecipients;
            int iRecipient;
            Boolean fFailBody = false;

            fFailBody = HasFailMarker(cnControl);

            cnEnveloped = cnInput["enveloped"];
            cnRecipients = cnEnveloped["recipients"];

            for (iRecipient = 0; iRecipient < cnRecipients.Count; iRecipient++) {
                CBORObject cnRecipient = cnRecipients[iRecipient];
                if (!cnRecipient.ContainsKey("recipients")) {
                    if (!DecryptMessage(rgbEncoded, fFailBody, cnEnveloped, cnRecipient, iRecipient, null, 0)) CFails++;
                }
                else {
                    int iRecipient2;
                    CBORObject cnRecipient2 = cnRecipient["recipients"];
                    for (iRecipient2 = 0; iRecipient2 < cnRecipient2.Count; iRecipient2++) {
                        if (!DecryptMessage(rgbEncoded, fFailBody, cnEnveloped, cnRecipient, iRecipient, cnRecipient2[iRecipient2], iRecipient2)) CFails++;
                    }
                }
            }
            return 0;
        }

        int VerifyEnvelopedTest(CBORObject cnControl)
        {
            String strExample = cnControl[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);

            return _ValidateEnveloped(cnControl, rgb);
        }

        Recipient BuildRecipient(CBORObject cnRecipient)
        {
            Recipient hRecip = new Recipient();


            SetSendingAttributes(hRecip, cnRecipient, true);

            CBORObject cnKey = cnRecipient[ "key"];
            if (cnKey != null) {
                OneKey pkey = BuildKey(cnKey, true);

                hRecip.SetKey(pkey);
            }

            cnKey = cnRecipient[ "recipients"];
            if (cnKey != null) {
                for (int i = 0; i < cnKey.Count; i++) {
                    Recipient hRecip2 = BuildRecipient(cnKey[ i]);
                    hRecip.AddRecipient(hRecip2);
                }
            }

            CBORObject cnSenderKey = cnRecipient[ "sender_key"];
            if (cnSenderKey != null) {
                OneKey cnSendKey = BuildKey(cnSenderKey, false);
                CBORObject cnKid = cnSenderKey[ "kid"];
                hRecip.SetSenderKey(cnSendKey);
                if (cnKid == null) {
                    hRecip.AddAttribute(HeaderKeys.ECDH_SPK, BuildKey(cnSenderKey, true).AsCBOR(), Attributes.UNPROTECTED);
                }
                else {
                    hRecip.AddAttribute(HeaderKeys.ECDH_SKID, cnKid, Attributes.UNPROTECTED);
                }
            }

            return hRecip;
        }

        void BuildEnvelopedTest(CBORObject cnControl)
        {
            int iRecipient;

            //
            //  We don't run this for all control sequences - skip those marked fail.
            //

            if (HasFailMarker(cnControl)) return;

            EncryptMessage hEncObj = new EncryptMessage();

            CBORObject cnInputs = cnControl[ "input"];
            CBORObject cnEnveloped = cnInputs[ "enveloped"];

            hEncObj.SetContent(GetContent(cnInputs));


            SetSendingAttributes(hEncObj, cnEnveloped, true);

            CBORObject cnRecipients = cnEnveloped[ "recipients"];

            for (iRecipient = 0; iRecipient < cnRecipients.Count; iRecipient++) {
                Recipient hRecip = BuildRecipient(cnRecipients[ iRecipient]);

                hEncObj.AddRecipient(hRecip);
            }

            hEncObj.Encrypt();

            byte[] rgb = hEncObj.EncodeToBytes();

            int f = _ValidateEnveloped(cnControl, rgb);

            return;
        }

        public void SetReceivingAttributes(Attributes msg, CBORObject cnIn)
        {
            SetAttributes(msg, cnIn[ "unsent"], Attributes.DO_NOT_SEND, true);

            CBORObject cnExternal = cnIn[ "external"];
            if (cnExternal != null) {
                msg.SetExternalData(hexStringToByteArray(cnExternal.AsString()));
            }
        }
        void SetSendingAttributes(Attributes msg, CBORObject cnIn, Boolean fPublicKey)
        {
            SetAttributes(msg, cnIn[ "protected"], Attributes.PROTECTED, fPublicKey);
            SetAttributes(msg, cnIn[ "unprotected"], Attributes.UNPROTECTED, fPublicKey);
            SetAttributes(msg, cnIn[ "unsent"], Attributes.DO_NOT_SEND, fPublicKey);

            CBORObject cnExternal = cnIn[ "external"];
            if (cnExternal != null) {
                msg.SetExternalData(hexStringToByteArray(cnExternal.AsString()));
            }
        }

        public void SetAttributes(Attributes msg, CBORObject cnAttributes, int which, Boolean fPublicKey)
        {
            if (cnAttributes == null) return;

            CBORObject cnKey;
            CBORObject cnValue;

            foreach (CBORObject attr in cnAttributes.Keys) {
                switch (attr.AsString()) {
                    case "alg":
                    cnKey = HeaderKeys.Algorithm;
                    cnValue = AlgorithmMap(cnAttributes[ attr]);
                    break;

                    case "kid":
                    cnKey = HeaderKeys.KeyId;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "spk_kid":
                    cnKey = HeaderKeys.ECDH_SKID;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "IV_hex":
                    cnKey = HeaderKeys.IV;
                    cnValue = CBORObject.FromObject(hexStringToByteArray(cnAttributes[ attr].AsString()));
                    break;

                    case "partialIV_hex":
                    cnKey = HeaderKeys.PartialIV;
                    cnValue = CBORObject.FromObject(hexStringToByteArray(cnAttributes[ attr].AsString()));
                    break;

                    case "salt":
                    cnKey = CoseKeyParameterKeys.HKDF_Salt;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apu_id":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyU_ID;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apv_id":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyV_ID;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apu_nonce":
                    case "apu_nonce_hex":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyU_nonce;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apv_nonce":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyV_nonce;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apu_other":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyU_Other;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "apv_other":
                    cnKey = CoseKeyParameterKeys.HKDF_Context_PartyV_Other;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "pub_other":
                    cnKey = CoseKeyParameterKeys.HKDF_SuppPub_Other;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "priv_other":
                    cnKey = CoseKeyParameterKeys.HKDF_SuppPriv_Other;
                    cnValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cnAttributes[ attr].AsString()));
                    break;

                    case "ctyp":
                    cnKey = HeaderKeys.ContentType;
                    cnValue = cnAttributes[ attr];
                    break;

                    case "crit":
                    cnKey = HeaderKeys.Critical;
                    cnValue = CBORObject.NewArray();
                    foreach (CBORObject x in cnAttributes[ attr].Values) {
                        cnValue.Add(HeaderMap(x));
                    }
                    break;

                    case "reserved":
                    cnKey = attr;
                    cnValue = cnAttributes[ attr];
                    break;

                    case "epk":
                    cnKey = null;
                    cnValue = null;
                    break;

                    default:
                    throw new Exception("Attribute " + attr.AsString() + " is not part of SetAttributes");
                }

                if (cnKey != null) {
                    msg.AddAttribute(cnKey, cnValue, which);
                }
            }
        }

        public OneKey BuildKey(CBORObject keyIn, Boolean fPublicKey)
        {
            CBORObject cnKeyOut = CBORObject.NewMap();

            foreach (CBORObject key in keyIn.Keys) {
                CBORObject cnValue = keyIn[ key];

                switch (key.AsString()) {
                    case "kty":
                    switch (cnValue.AsString()) {
                        case "EC":
                        cnKeyOut[CBORObject.FromObject(1)] = CBORObject.FromObject(2);
                        break;

                        case "oct":
                        cnKeyOut[CBORObject.FromObject(1)] = CBORObject.FromObject(4);
                        break;

                        case "OKP":
                        cnKeyOut[CBORObject.FromObject(1)] = GeneralValues.KeyType_OKP;
                        break;
                    }
                    break;

                    case "crv":
                    switch (cnValue.AsString()) {
                        case "P-256":
                        cnValue = CBORObject.FromObject(1);
                        break;

                        case "P-384":
                        cnValue = CBORObject.FromObject(2);
                        break;

                        case "P-521":
                        cnValue = CBORObject.FromObject(3);
                        break;

                        case "X25519":
                        cnValue = GeneralValues.X25519;
                        break;

                        default:
                        break;
                    }


                    cnKeyOut[CBORObject.FromObject(-1)] = cnValue;
                    break;

                    case "x":
                    cnKeyOut[CoseKeyParameterKeys.EC_X] = CBORObject.FromObject(base64urldecode(cnValue.AsString()));
                    break;

                case "x_hex":
                        cnKeyOut[CoseKeyParameterKeys.EC_X] = CBORObject.FromObject(hexStringToByteArray(cnValue.AsString()));
                        break;

                    case "y":
                    cnKeyOut[CoseKeyParameterKeys.EC_Y] = CBORObject.FromObject(base64urldecode(cnValue.AsString()));
                    break;

                case "y_hex":
                    cnKeyOut[CoseKeyParameterKeys.EC_Y] = CBORObject.FromObject(hexStringToByteArray(cnValue.AsString()));
                    break;

                case "d":
                    if (!fPublicKey) {
                        cnKeyOut[CoseKeyParameterKeys.EC_D] = CBORObject.FromObject(base64urldecode(cnValue.AsString()));
                    }
                    break;

                    case "d_hex":
                        if (!fPublicKey) {
                            cnKeyOut[CoseKeyParameterKeys.EC_D] = CBORObject.FromObject(hexStringToByteArray(cnValue.AsString()));
                        }
                        break;

                case "k":
                    cnKeyOut[CBORObject.FromObject(-1)] = CBORObject.FromObject(base64urldecode(cnValue.AsString()));
                    break;

                    case "k_hex":
                        cnKeyOut[CBORObject.FromObject(-1)] = CBORObject.FromObject(hexStringToByteArray(cnValue.AsString()));
                        break;

                case "kid":
                case "use":
                    break;

                default:
                    throw new Exception("Unknown parameter in BuildKey");
                }
            }

            return new OneKey(cnKeyOut);
        }

        public byte[] hexStringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static CBORObject AlgorithmMap(CBORObject old)
        {
            if (old.Type == CBORType.Number) {
                return old;
            }

            switch (old.AsString()) {
                case "A128GCM": return AlgorithmValues.AES_GCM_128;
                case "A192GCM": return AlgorithmValues.AES_GCM_192;
                case "A256GCM": return AlgorithmValues.AES_GCM_256;
                case "A128KW": return AlgorithmValues.AES_KW_128;
                case "A192KW": return AlgorithmValues.AES_KW_192;
                case "A256KW": return AlgorithmValues.AES_KW_256;
                // case "RSA-OAEP": return AlgorithmValues.RSA_OAEP;
                // case "RSA-OAEP-256": return AlgorithmValues.RSA_OAEP_256;
                case "HS256": return AlgorithmValues.HMAC_SHA_256;
                case "HS256/64": return AlgorithmValues.HMAC_SHA_256_64;
                case "HS384": return AlgorithmValues.HMAC_SHA_384;
                case "HS512": return AlgorithmValues.HMAC_SHA_512;
                case "ES256": return AlgorithmValues.ECDSA_256;
                case "ES384": return AlgorithmValues.ECDSA_384;
                case "ES512": return AlgorithmValues.ECDSA_512;
                // case "PS256": return AlgorithmValues.RSA_PSS_256;
                // case "PS512": return AlgorithmValues.RSA_PSS_512;
                case "direct": return AlgorithmValues.Direct;
                //case "AES-CMAC-128/64": return AlgorithmValues.AES_CMAC_128_64;
                //case "AES-CMAC-256/64": return AlgorithmValues.AES_CMAC_256_64;
                case "AES-MAC-128/64": return AlgorithmValues.AES_CBC_MAC_128_64;
                case "AES-MAC-256/64": return AlgorithmValues.AES_CBC_MAC_256_64;
                case "AES-MAC-128/128": return AlgorithmValues.AES_CBC_MAC_128_128;
                case "AES-MAC-256/128": return AlgorithmValues.AES_CBC_MAC_256_128;
                case "AES-CCM-16-128/64": return AlgorithmValues.AES_CCM_16_64_128;
                case "AES-CCM-16-128/128": return AlgorithmValues.AES_CCM_16_128_128;
                case "AES-CCM-16-256/64": return AlgorithmValues.AES_CCM_16_64_256;
                case "AES-CCM-16-256/128": return AlgorithmValues.AES_CCM_16_128_256;
                case "AES-CCM-64-128/64": return AlgorithmValues.AES_CCM_64_64_128;
                case "AES-CCM-64-128/128": return AlgorithmValues.AES_CCM_64_128_128;
                case "AES-CCM-64-256/64": return AlgorithmValues.AES_CCM_64_64_256;
                case "AES-CCM-64-256/128": return AlgorithmValues.AES_CCM_64_128_256;
                case "HKDF-HMAC-SHA-256": return AlgorithmValues.HKDF_HMAC_SHA_256;
                case "HKDF-HMAC-SHA-512": return AlgorithmValues.HKDF_HMAC_SHA_512;
                case "HKDF-AES-128": return AlgorithmValues.HKDF_AES_128;
                case "HKDF-AES-256": return AlgorithmValues.HKDF_AES_256;
                case "ECDH-ES": return AlgorithmValues.ECDH_ES_HKDF_256;
                case "ECDH-ES-512": return AlgorithmValues.ECDH_ES_HKDF_512;
                case "ECDH-SS": return AlgorithmValues.ECDH_SS_HKDF_256;
                case "ECDH-SS-256": return AlgorithmValues.ECDH_SS_HKDF_256;
                case "ECDH-SS-512": return AlgorithmValues.ECDH_SS_HKDF_512;
                case "ECDH-ES+A128KW": return AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128;
                case "ECDH-SS+A128KW": return AlgorithmValues.ECDH_SS_HKDF_256_AES_KW_128;
                case "ECDH-ES-A128KW": return AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128;
                case "ECDH-SS-A128KW": return AlgorithmValues.ECDH_SS_HKDF_256_AES_KW_128;
                case "ECDH-ES-A192KW": return AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_192;
                case "ECDH-SS-A192KW": return AlgorithmValues.ECDH_SS_HKDF_256_AES_KW_192;
                case "ECDH-ES-A256KW": return AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_256;
                case "ECDH-SS-A256KW": return AlgorithmValues.ECDH_SS_HKDF_256_AES_KW_256;

                default: return old;
            }
        }

        static CBORObject HeaderMap(CBORObject obj)
        {
            switch (obj.AsString()) {
                default:
                return obj;

            }
        }

        public Boolean HasFailMarker(CBORObject cn)
        {
            CBORObject cnFail = cn[ "fail"];
            if (cnFail != null && cnFail.AsBoolean()) return true;
            return false;
        }

        int _ValidateSigned(CBORObject cnControl, byte[] pbEncoded)
        {
            CBORObject cnInput = cnControl[ "input"];
            CBORObject cnSign;
            CBORObject cnSigners;
            SignMessage hSig = null;
            int iSigner;
            Boolean fFailBody;

            fFailBody = HasFailMarker(cnControl);

            try {
                cnSign = cnInput[ "sign"];
                cnSigners = cnSign[ "signers"];

                for (iSigner = 0; iSigner < cnSigners.Count; iSigner++) {

                    try {
                        Message msg = Message.DecodeFromBytes(pbEncoded, Tags.Sign);
                        hSig = (SignMessage)msg;
                    }
                    catch (Exception) {
                        if (fFailBody) return 0;

                    }

                    SetReceivingAttributes(hSig, cnSign);

                    OneKey cnkey = BuildKey(cnSigners[ iSigner][ "key"], false);

                    Signer hSigner = hSig.SignerList[iSigner];

                    SetReceivingAttributes(hSigner, cnSigners[ iSigner]);

                    hSigner.SetKey(cnkey);

                    Boolean fFailSigner = HasFailMarker(cnSigners[ iSigner]);

                    try {
                        Boolean f = hSig.Validate(hSigner);
                        if (!f && !(fFailBody || fFailSigner)) CFails++;
                    }
                    catch (Exception) {
                        if (!fFailBody && !fFailSigner) CFails++;
                    }

#if false
                    CBORObject cSignInfo = cnSign[ "countersign"];
                    if (cSignInfo != null) {
                        CheckCounterSignatures(hSig, cSignInfo);
                    }
#endif
                }
            }
            catch (Exception e) {
                Console.Write("... FAIL\nException " + e + "\n");
                CFails++;
            }
            return 0;
        }

        int ValidateSigned(CBORObject cnControl)
        {
            String strExample = cnControl[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);

            return _ValidateSigned(cnControl, rgb);
        }

        int BuildSignedMessage(CBORObject cnControl)
        {
            int iSigner;
            byte[] rgb;

            //
            //  We don't run this for all control sequences - skip those marked fail.
            //

            if (HasFailMarker(cnControl)) return 0;

            try {
                SignMessage hSignObj = new SignMessage();

                CBORObject cnInputs = cnControl[ "input"];
                CBORObject cnSign = cnInputs[ "sign"];

                hSignObj.SetContent(GetContent(cnInputs));

                SetSendingAttributes(hSignObj, cnSign, false);

                CBORObject cnSigners = cnSign[ "signers"];

                for (iSigner = 0; iSigner < cnSigners.Count; iSigner++) {
                    OneKey cnkey = BuildKey(cnSigners[ iSigner][ "key"], false);

                    Signer hSigner = new Signer();

                    SetSendingAttributes(hSigner, cnSigners[ iSigner], false);

                    hSigner.SetKey(cnkey);

                    hSignObj.AddSigner(hSigner);

                }

                // hSignObj.Sign();

#if false
                CBORObject cnCounterSign = cnSign[ "countersign"];
                if (cnCounterSign != null) {
                    CreateCounterSignatures(hSignObj, cnCounterSign);
                }
#endif
                rgb = hSignObj.EncodeToBytes();
            }
            catch (Exception e) {
                Console.Write("... Exception " + e + "\n");

                CFails++;
                return 0;
            }

            int f = _ValidateSigned(cnControl, rgb);
            return f;
        }

        int _ValidateSign0(CBORObject cnControl, byte[] pbEncoded)
        {
            CBORObject cnInput = cnControl[ "input"];
            CBORObject cnSign;
            Sign1Message hSig;
            Boolean fFail;

            try {
                fFail = HasFailMarker(cnControl);

                cnSign = cnInput[ "sign0"];

                try {
                    Message msg = Message.DecodeFromBytes(pbEncoded, Tags.Sign1);
                    hSig = (Sign1Message)msg;
                }
                catch (CoseException) {
                    if (!fFail) CFails++;
                    return 0;
                }


                SetReceivingAttributes(hSig, cnSign);

                OneKey cnkey = BuildKey(cnSign[ "key"], true);

                Boolean fFailInput = HasFailMarker(cnInput);

                try {
                    Boolean f = hSig.Validate(cnkey);
                    if (f && (fFail || fFailInput)) CFails++;
                    if (!f && !(fFail || fFailInput)) CFails++;
                }
                catch (Exception) {
                    if (!fFail && !fFailInput) CFails++;
                }
            }
            catch (Exception) {
                CFails++;
            }
            return 0;
        }

        int ValidateSign0(CBORObject cnControl)
        {
            String strExample = cnControl[ "output"][ "cbor"].AsString();
            byte[] rgb = hexStringToByteArray(strExample);

            return _ValidateSign0(cnControl, rgb);
        }

        int BuildSign0Message(CBORObject cnControl)
        {
            byte[] rgb;
            //
            //  We don't run this for all control sequences - skip those marked fail.
            //

            if (HasFailMarker(cnControl)) return 0;

            try {
                Sign1Message hSignObj = new Sign1Message();

                CBORObject cnInputs = cnControl[ "input"];
                CBORObject cnSign = cnInputs[ "sign0"];

                hSignObj.SetContent(GetContent(cnInputs));

                SetSendingAttributes(hSignObj, cnSign, false);

                OneKey cnkey = BuildKey(cnSign[ "key"], false);

                hSignObj.Sign(cnkey);

                rgb = hSignObj.EncodeToBytes();
            }
            catch (Exception) {
                CFails++;
                return 0;
            }

            int f = _ValidateSign0(cnControl, rgb);
            return 0;
        }
#if false
        void CreateCounterSignatures(Message msg, CBORObject cSigInfo)
        {
            try {
                CBORObject cnResult = CBORObject.NewArray();

                CBORObject cSigConfig = cSigInfo[ "signers"];


                foreach (CBORObject csig in cSigConfig.Values) {
                    OneKey cnKey = BuildKey(csig[ "key"], false);

                    CounterSignature sig = new CounterSignature();

                    SetSendingAttributes(sig, csig, false);

                    sig.SetKey(cnKey);

                    sig.Sign(msg);

                    if (cSigConfig.Count == 1) cnResult = sig.EncodeToCBORObject();
                    else cnResult.Add(sig.EncodeToBytes());
                }

                msg.AddAttribute(HeaderKeys.CounterSignature, cnResult, Attributes.UNPROTECTED);

            }
            catch (Exception e) {
                CFails++;
            }
        }
        void CheckCounterSignatures(Message msg, CBORObject cSigInfo)
        {
            try {
                CBORObject cSigs = msg.FindAttribute(HeaderKeys.CounterSignature);
                if (cSigs == null) {
                    CFails++;
                    return;
                }

                if (cSigs.Type != CBORType.Array) {
                    CFails++;
                    return;
                }

                CBORObject cSigConfig = cSigInfo[ "signers"];
                if ((cSigConfig.Count > 1) && (cSigs.Count != cSigConfig.Count)) {
                    CFails++;
                    return;
                }

                int iCSign;
                for (iCSign = 0; iCSign < cSigConfig.Count; iCSign++) {
                    CounterSignature sig;
                    if (cSigs[ 0].Type != CBORType.Array) {
                        sig = new CounterSignature();
                        sig.DecodeFromCBORObject(cSigs);
                    }
                    else {
                        sig = new CounterSignature(cSigs[ iCSign].GetByteString());
                    }

                    OneKey cnKey = BuildKey(cSigConfig[ iCSign][ "key"], false);
                    SetReceivingAttributes(sig, cSigConfig[ iCSign]);

                    sig.SetKey(cnKey);

                    try {
                        Boolean f = sig.Validate(msg);
                        if (!f) CFails++;
                    }
                    catch (Exception e) {
                        CFails++;
                    }
                }
            }
            catch (Exception e) {
                Console.Write("... FAIL\nException " + e + "\n");
                CFails++;
            }
        }
#endif

        byte[] GetContent(CBORObject cnInputs)
        {
            if (cnInputs.ContainsKey("plaintext")) return Encoding.UTF8.GetBytes(  cnInputs["plaintext"].AsString());
            if (cnInputs.ContainsKey("plaintext_hex")) return hexStringToByteArray(cnInputs["plaintext_hex"].AsString());
            throw new Exception("Missing content");
        }

        static byte[] base64urldecode(string arg)
        {
            string s = arg;
            s = s.Replace('-', '+'); // 62nd char of encoding
            s = s.Replace('_', '/'); // 63rd char of encoding
            switch (s.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 2: s += "=="; break; // Two pad chars
                case 3: s += "="; break; // One pad char
                default:
                throw new System.Exception(
         "Illegal base64url string!");
            }
            return Convert.FromBase64String(s); // Standard base64 decoder
        }
    }
}
