using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;

using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace examples
{


    class Program
    {
        enum Outputs { cbor = 1, cborDiag = 2, jose = 3, jose_compact = 4, jose_flatten = 5 };

        static Outputs[] RgOutputs = new Outputs[] { Outputs.cborDiag, Outputs.cbor  /*, Outputs.cbor, Outputs.cborFlatten*/ };

        static KeySet allkeys = new KeySet();
        static KeySet allPubKeys = new KeySet();

        static string RootDir = "c:\\projects\\COSE\\examples";

        static void Main(string[] args)
        {
            if (args.Count() == 0) {
                // RunCoseExamples();
                JoseExamples.RunTestsInDirectory(@"c:\Projects\JOSE\cookbook");
                return;
            }

            for (int i = 0; i < args.Count(); i++) {
                switch (args[i]) {
                case "--cose":
                    RootDir = "";
                    i++;
                    if (i > args.Count()) PrintCommandLine();
                    RunTestsInDirectory(args[i]);
                    break;

                case "--jose":
                    i++;
                    if (i > args.Count()) PrintCommandLine();
                    JoseExamples.RunTestsInDirectory(args[i]);
                    break;

                default:
                    PrintCommandLine();
                    break;
                }
            }
        }

        static void PrintCommandLine()
        {
            Console.WriteLine("Command line for test program is: ");
            Console.WriteLine("example [--cose directory] [--jose directory]");
            Environment.Exit(1);    
        }

        static void RunCoseExamples()
        { 
            Key.NewKey();

            EdDSA25517.SelfTest();
            EdDSA448.SelfTest();

            Recipient.FUseCompressed = true;
            RunTestsInDirectory("X25519-tests");

            RunTestsInDirectory("spec-examples");
            {
                byte[] result = allkeys.EncodeToBytes();

                FileStream bw = File.OpenWrite(RootDir + "\\new\\spec-examples\\private-keyset.bin");
                bw.SetLength(0);
                bw.Write(result, 0, result.Length);
                bw.Close();

                bw = File.OpenWrite(RootDir + "\\new\\spec-examples\\public-keyset.bin");
                bw.SetLength(0);
                result = allPubKeys.EncodeToBytes();
                bw.Write(result, 0, result.Length);
                bw.Close();

            }

            Recipient.FUseCompressed = false;

            RunTestsInDirectory("hmac-examples");
            RunTestsInDirectory("cbc-mac-examples");
            RunTestsInDirectory("aes-ccm-examples");
            RunTestsInDirectory("aes-gcm-examples");
            RunTestsInDirectory("chacha-poly-examples");
            RunTestsInDirectory("ecdsa-examples");
            RunTestsInDirectory("hkdf-hmac-sha-examples");
            RunTestsInDirectory("hkdf-aes-examples");
            RunTestsInDirectory("aes-wrap-examples");
            RunTestsInDirectory("ecdh-direct-examples");
            RunTestsInDirectory("ecdh-wrap-examples");
            RunTestsInDirectory("mac-tests");
            RunTestsInDirectory("mac0-tests");
            RunTestsInDirectory("enveloped-tests");
            RunTestsInDirectory("encrypted-tests");
            RunTestsInDirectory("sign-tests");
            RunTestsInDirectory("sign1-tests");
        }

        static void RunTestsInDirectory(string strDirectory)
        {
            DirectoryInfo diTop;

            diTop = new DirectoryInfo(Path.Combine(RootDir, strDirectory));
            foreach (var di in diTop.EnumerateDirectories()) {
                if ((!di.Attributes.HasFlag(FileAttributes.Hidden)) &&
                    (di.FullName.Substring(di.FullName.Length - 4) != "\\new")) {
                    RunTestsInDirectory(Path.Combine(strDirectory, di.Name));
                }
            }

            foreach (var di in diTop.EnumerateFiles()) {
                if (di.Extension == ".json") {
                    ProcessFile(strDirectory, di.Name);
                }
            }
        }

        static void ProcessFile(String dir, String fileName)
        {
            StreamReader file = File.OpenText(Path.Combine(RootDir, dir, fileName));
            string fileText = file.ReadToEnd();
            CBORObject control = CBORObject.FromJSONString(fileText);
            file.Close();

#if FOR_EXAMPLES
            Directory.CreateDirectory(RootDir + "\\new\\" + dir);
#else
            Console.Write(Path.Combine(RootDir, dir, fileName));
#endif


            try {
#if FOR_EXAMPLES
                if (ProcessJSON(control, RootDir + "\\new\\" + dir + "\\" + fileName.Replace(".json", ".bin"))) {
                    fileText = control.ToJSONStringPretty(1);
                    StreamWriter file2 = File.CreateText(RootDir + "\\new\\" + dir + "\\" + fileName);
                    file2.Write(fileText);
                    file2.Write("\r\n");
                    file2.Close();
            }
#endif

                ValidateJSON(control);
            }
            catch (Exception e) {
                Console.WriteLine("ERROR: " + e.ToString());
            }
        }

#if FOR_EXAMPLES
        static bool ProcessJSON(CBORObject control, string fileName)
        {
            bool modified = false;
            StaticPrng prng = new StaticPrng();

            if (control.ContainsKey("title")) {
                Console.Write("Processing: " + control["title"].AsString());
            }

            if (control["input"].ContainsKey("rng_stream")) {
                if (control["input"]["rng_stream"].Type == CBORType.TextString) {
                    prng.AddSeedMaterial(FromHex(control["input"]["rng_stream"].AsString()));
                }
                else if (control["input"]["rng_stream"].Type == CBORType.Array) {
                    foreach (var x in control["input"]["rng_stream"].Values) {
                        prng.AddSeedMaterial(FromHex(x.AsString()));
                    }
                }
            }
            Message.SetPRNG(prng);
            JOSE.Message.SetPRNG(prng);

            prng.Reset();

            try {
                CBORObject result;

                if (control["input"].ContainsKey("mac")) result = ProcessMAC(control, ref modified);
                else if (control["input"].ContainsKey("mac0")) result = ProcessMAC0(control, ref modified);
                else if (control["input"].ContainsKey("enveloped")) result = ProcessEnveloped(control, ref modified);
                else if (control["input"].ContainsKey("encrypted")) result = ProcessEncrypted(control, ref modified);
                else if (control["input"].ContainsKey("sign")) result = ProcessSign(control, ref modified);
                else if (control["input"].ContainsKey("sign0")) result = ProcessSign0(control, ref modified);
                else throw new Exception("Unknown operation in control");

                byte[] rgbNew = result.EncodeToBytes();
                if (control["output"].ContainsKey("cbor")) {
                    byte[] rgbSource = FromHex(control["output"]["cbor"].AsString());
                    if (!rgbSource.SequenceEqual(rgbNew)) {
                        Console.WriteLine();
                        Console.WriteLine("******************* New and Old do not match!!!");
                        Console.WriteLine();

                        control["output"]["cbor"] = CBORObject.FromObject(ToHex(rgbNew));
                        modified = true;
                    }
                }
                else {
                    control["output"].Add("cbor", ToHex(rgbNew));
                    modified = true;
                }
                FileStream bw = File.OpenWrite(fileName);
                bw.SetLength(0);
                bw.Write(rgbNew, 0, rgbNew.Length);
                bw.Close();

                if (control["output"].ContainsKey("cbor_diag")) {
                    string strSource = control["output"]["cbor_diag"].ToString();
                    string strThis = result.ToString();

                    if (strSource != strThis) {
                        control["output"]["cbor_diag"] = CBORObject.FromObject(strThis);
                        modified = true;
                    }
                }
                else {
                    control["output"].Add("cbor_diag", result.ToString());
                    modified = true;
                }


                if (prng.IsDirty) {
                    if (prng.buffer != null) {
                        if (control["input"].ContainsKey("rng_stream")) control["input"]["rng_stream"] = prng.buffer;
                        else control["input"].Add("rng_stream", prng.buffer);
                    }
                    else {
                        if (control["input"].ContainsKey("rng_stream")) control["input"].Remove(CBORObject.FromObject("rng_stream"));
                    }
                    modified = true;
                }
            }
            catch (CoseException e) {
                Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
            }
            catch (JOSE.JOSE_Exception e) {
                Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
            }

            return modified;
        }
#endif

#if FOR_EXAMPLES
        static CBORObject ProcessSign(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject sign = input["sign"];
            CBORObject signers;

            SignMessage msg = new SignMessage();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], 0);
            if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], 1);
            if (sign.ContainsKey("unsent")) AddAttributes(msg, sign["unsent"], 2);
            if (sign.ContainsKey("countersign")) AddCounterSignature(msg, sign["countersign"]);

            if ((!sign.ContainsKey("signers")) || (sign["signers"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
            foreach (CBORObject recip in sign["signers"].Values) {
                msg.AddSigner(GetSigner(recip));
            }

            {
                msg.Encode();

                signers = GetSection(GetSection(control, "intermediates"), "signers");

                for (int iSigner = 0; iSigner < msg.SignerList.Count; iSigner++) {
                    CBORObject sig = signers[iSigner];

                    SetField(signers[iSigner], "ToBeSign_hex", msg.SignerList[iSigner].GetToBeSigned(), ref fDirty);
                }

                if (msg.CounterSignerList.Count > 0) {
                    signers = GetSection(GetSection(control, "intermediates"), "countersigners");
                    for (int iSigner = 0; iSigner < msg.CounterSignerList.Count; iSigner++) {
                        CBORObject sig = signers[iSigner];

                        SetField(signers[iSigner], "ToBeSign_hex", msg.CounterSignerList[iSigner].GetToBeSigned(), ref fDirty);

                    }
                }
            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 99);
            }

            signers = sign["signers"];

            for (int iRecip = 0; iRecip < signers.Values.Count; iRecip++) {
                if (signers[iRecip].ContainsKey("failures")) {
                    ProcessFailures(msgOut.Untag()[3][iRecip], signers[iRecip]["failures"], 2);
                }
            }

            return msgOut;
        }
#endif

#if FOR_EXAMPLES
        static CBORObject ProcessSign0(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject sign = input["sign0"];

            Sign0Message msg = new Sign0Message();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (!sign.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            Key key = GetKey(sign["key"]);

            msg.AddSigner(key, AlgorithmMap(sign["alg"]));

            if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], 0);
            if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], 1);
            if (sign.ContainsKey("unsent")) AddAttributes(msg, sign["unsent"], 2);
            if (sign.ContainsKey("external")) AddExternalData(msg, sign["external"]);

            {
                msg.Encode();

                SetField(GetSection(control, "intermediates"), "ToBeSign_hex", msg.GetToBeSigned(), ref fDirty);

            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 2);
            }
            return msgOut;
        }
#endif

        static bool ValidateSign0(CBORObject cnControl)
        {
            CBORObject cnInput = cnControl["input"];
            CBORObject cnSign;
            Sign1Message hSig;
            bool fFail;

            byte[] rgb = FromHex(cnControl["output"]["cbor"].AsString());

            fFail = HasFailMarker(cnControl);

                cnSign = cnInput["sign0"];

            try {
                Message msg = Message.DecodeFromBytes(rgb, Tags.Signed0);
                hSig = (Sign1Message) msg;
            }
            catch (CoseException) {
                if (fFail) return true;
                return false;
            }

            SetRecievingAttributes(hSig, cnSign);

            Key cnkey = GetKey(cnSign["key"], true);

            bool fFailInput = HasFailMarker(cnInput);

            try {
                bool f = hSig.Validate(cnkey);
                if (f && (fFail || fFailInput)) return false;
                if (!f && !(fFail || fFailInput)) return false;
            }
            catch (Exception) {
                if (fFail || fFailInput) return true;
                return false;
            }
            
            return true;
        }


#if FOR_EXAMPLES
        static CBORObject ProcessEncrypted(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["encrypted"];

            EncryptMessage msg = new EncryptMessage();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], 0);
            if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], 1);
            if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);
            if (encrypt.ContainsKey("countersign")) AddCounterSignature(msg, encrypt["countersign"]);
            if (encrypt.ContainsKey("external")) AddExternalData(msg, encrypt["external"]);

            if (encrypt.ContainsKey("alg")) {
                encrypt.Remove(CBORObject.FromObject("alg"));
            }

            if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");

            byte[] rgbKey;

            Key key;
            key = GetKey(encrypt["recipients"][0]["key"]);

            rgbKey = key[CoseKeyParameterKeys.Octet_k].GetByteString();

            {
                msg.Encrypt(rgbKey);

                CBORObject intermediates = GetSection(control, "intermediates");

                SetField(intermediates, "AAD_hex", msg.getAADBytes(), ref fDirty);
                SetField(intermediates, "CEK_hex", msg.getCEK(), ref fDirty);
            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 2);
            }
            return msgOut;
        }
#endif

        static bool ValidateEncrypted(CBORObject control)
        {
            CBORObject cnInput = control["input"];
            Boolean fFail = false;
            Boolean fFailBody = false;

            CBORObject cnFail = control["fail"];
            if ((cnFail != null) && (cnFail.Type == CBORType.Boolean) &&
                  cnFail.AsBoolean()) {
                fFailBody = true;
            }

            byte[] rgbData = FromHex(control["output"]["cbor"].AsString());

            try {
                Message msg = Message.DecodeFromBytes(rgbData, Tags.Encrypted);
                Encrypt0Message enc0 = (Encrypt0Message) msg;

                CBORObject cnEncrypt = cnInput["encrypted"];
                SetRecievingAttributes(msg, cnEncrypt);

                CBORObject cnRecipients = cnEncrypt["recipients"];
                cnRecipients = cnRecipients[0];

                Key cnKey = GetKey(cnRecipients["key"], true);

                CBORObject kk = cnKey[CBORObject.FromObject(-1)];

                cnFail = cnRecipients["fail"];

                try {
                    byte[] rgbContent = enc0.Decrypt(kk.GetByteString());
                    if ((cnFail != null) && !cnFail.AsBoolean()) return false; 
                }
                catch (Exception) {
                    if (!fFailBody && ((cnFail == null) || !cnFail.AsBoolean())) return false;
                }
            }
            catch (Exception) {
                if (!fFailBody) return false;
            }

            return true;
        }

#if FOR_EXAMPLES
        static CBORObject ProcessEnveloped(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["enveloped"];

            EnvelopedMessage msg = new EnvelopedMessage();

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], 0);
            if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], 1);
            if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);
            if (encrypt.ContainsKey("countersign")) AddCounterSignature(msg, encrypt["countersign"]);
            if (encrypt.ContainsKey("external")) AddExternalData(msg, encrypt["external"]);

            if (encrypt.ContainsKey("alg")) {
                encrypt.Remove(CBORObject.FromObject("alg"));
            }

            if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
            foreach (CBORObject recip in encrypt["recipients"].Values) {
                msg.AddRecipient(GetRecipient(recip));
            }

            {
                msg.Encode();

                CBORObject intermediates = GetSection(control, "intermediates");

                SetField(intermediates, "AAD_hex", msg.getAADBytes(), ref fDirty);
                SetField(intermediates, "CEK_hex", msg.getCEK(), ref fDirty);

                CBORObject rList = GetSection(intermediates, "recipients");

                for (int iRecipient = 0; iRecipient < msg.RecipientList.Count; iRecipient++) {
                    Recipient r = msg.RecipientList[iRecipient];

                    SetField(rList[iRecipient], "Context_hex", r.getContext(), ref fDirty);
                    SetField(rList[iRecipient], "Secret_hex", r.getSecret(), ref fDirty);
                    SetField(rList[iRecipient], "KEK_hex", r.getKEK(), ref fDirty);

                    if (r.RecipientList.Count > 0) {
                        CBORObject rList2 = GetSection(rList[iRecipient], "recipients");

                        for (int iRecipient2 = 0; iRecipient2 < r.RecipientList.Count; iRecipient2++) {
                            Recipient r2 = r.RecipientList[iRecipient2];

                            SetField(rList2[iRecipient2], "Context_hex", r2.getContext(), ref fDirty);
                            SetField(rList2[iRecipient2], "Secret_hex", r2.getSecret(), ref fDirty);
                            SetField(rList2[iRecipient2], "KEK_hex", r2.getKEK(), ref fDirty);

                        }
                    }
                }

                if (msg.CounterSignerList.Count > 0) {
                    CBORObject signers = GetSection(GetSection(control, "intermediates"), "countersigners");
                    for (int iSigner = 0; iSigner < msg.CounterSignerList.Count; iSigner++) {
                        CBORObject sig = signers[iSigner];

                        SetField(signers[iSigner], "ToBeSign_hex", msg.CounterSignerList[iSigner].GetToBeSigned(), ref fDirty);

                    }
                }

            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 2);
            }
            return msgOut;
        }
#endif

#if FOR_EXAMPLES
        static CBORObject ProcessMAC(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject mac = input["mac"];

            MACMessage msg = new MACMessage();

            if (control.ContainsKey("alg")) {
                control.Remove(CBORObject.FromObject("alg"));
            }

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], 0);
            if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], 1);
            if (mac.ContainsKey("unsent")) AddAttributes(msg, mac["unsent"], 2);
            if (mac.ContainsKey("external")) AddExternalData(msg, mac["external"]);

            if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");

            foreach (CBORObject recip in mac["recipients"].Values) {
                msg.AddRecipient(GetRecipient(recip));
            }

            msg.MAC();

            CBORObject intermediates = GetSection(control, "intermediates");

            SetField(intermediates, "ToMac_hex", msg.BuildContentBytes(), ref fDirty);
            SetField(intermediates, "CEK_hex", msg.getCEK(), ref fDirty);

            CBORObject rList = GetSection(intermediates, "recipients");

            for (int iRecipient = 0; iRecipient < msg.RecipientList.Count; iRecipient++) {
                Recipient r = msg.RecipientList[iRecipient];

                SetField(rList[iRecipient], "Context_hex", r.getContext(), ref fDirty);
                SetField(rList[iRecipient], "Secret_hex", r.getSecret(), ref fDirty);
                SetField(rList[iRecipient], "KEK_hex", r.getKEK(), ref fDirty);

                if (r.RecipientList.Count > 0) {
                    CBORObject rList2 = GetSection(rList[iRecipient], "recipients");

                    for (int iRecipient2 = 0; iRecipient2 < r.RecipientList.Count; iRecipient2++) {
                        Recipient r2 = r.RecipientList[iRecipient2];

                        SetField(rList2[iRecipient2], "Context_hex", r2.getContext(), ref fDirty);
                        SetField(rList2[iRecipient2], "Secret_hex", r2.getSecret(), ref fDirty);
                        SetField(rList2[iRecipient2], "KEK_hex", r2.getKEK(), ref fDirty);

                    }
                }
            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 3);
            }
            return msgOut;
        }
#endif

#if FOR_EXAMPLES
        static CBORObject ProcessMAC0(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject mac = input["mac0"];

            MAC0Message msg = new MAC0Message();

            if (control.ContainsKey("alg")) {
                control.Remove(CBORObject.FromObject("alg"));
            }

            msg.ForceArray(true);

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (mac.ContainsKey("protected")) AddAttributes(msg, mac["protected"], 0);
            if (mac.ContainsKey("unprotected")) AddAttributes(msg, mac["unprotected"], 1);
            if (mac.ContainsKey("unsent")) AddAttributes(msg, mac["unsent"], 2);
            if (mac.ContainsKey("external")) AddExternalData(msg, mac["external"]);

            if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");

            Key key;

            key = GetKey(mac["recipients"][0]["key"]);

            {
                byte[] rgbKey = key[CoseKeyParameterKeys.Octet_k].GetByteString();
                msg.Compute(rgbKey);

                CBORObject intermediates = GetSection(control, "intermediates");

                SetField(intermediates, "ToMac_hex", msg.BuildContentBytes(), ref fDirty);
                SetField(intermediates, "CEK_hex", rgbKey, ref fDirty);
            }

            CBORObject msgOut = msg.EncodeToCBORObject();

            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures")) {
                msgOut = ProcessFailures(msgOut, input["failures"], 3);
            }
            return msgOut;
        }
#endif

        static public Boolean ValidateMac0(CBORObject control)
        {
            CBORObject cnInput = control["input"];
            Boolean fFail = false;
            Boolean fFailBody = false;
            byte[] rgbData = FromHex(control["output"]["cbor"].AsString());


            try {
                fFailBody = HasFailMarker(control);

                Message msg = Message.DecodeFromBytes(rgbData, Tags.MAC0);
                MAC0Message mac0 = (MAC0Message) msg;

                CBORObject cnMac = cnInput["mac0"];
                SetRecievingAttributes(msg, cnMac);

                CBORObject cnRecipients = cnMac["recipients"];
                cnRecipients = cnRecipients[0];

                Key cnKey = GetKey(cnRecipients["key"], true);

                CBORObject kk = cnKey[CBORObject.FromObject(-1)];

                fFail = HasFailMarker(cnRecipients);


                Boolean f = mac0.Validate(cnKey);

                if (f) {
                    if (fFail || fFailBody) return false;
                }
                else {
                    if (!fFail && !fFailBody) return false;
                }

            }
            catch (Exception) {
                if (!fFailBody) return false;
            }

            return true;
        }

#if FOR_EXAMPLES
        static CBORObject ProcessFailures(CBORObject msgOut, CBORObject failures, int iTag)
        {
            foreach (CBORObject failure in failures.Keys) {
                switch (failure.AsString()) {
                case "ChangeTag": // Alter the validate tag
                    byte[] rgb = msgOut.Untag()[iTag].GetByteString();
                    rgb[rgb.Length - 1] = (byte) (rgb[rgb.Length - 1] + 1);
                    break;

                case "ChangeCBORTag":
                    msgOut = CBORObject.FromObjectAndTag(msgOut.Untag(), failures["ChangeCBORTag"].AsInt32());
                    break;

                case "AddProtected":
                case "ChangeAttr": {
                        CBORObject protect;
                        if (msgOut.Untag()[0].GetByteString().Length > 0) {
                            protect = CBORObject.DecodeFromBytes(msgOut.Untag()[0].GetByteString());
                        }
                        else protect = CBORObject.NewMap();
                        AddAttributes(protect, failures[failure.AsString()]);
                        msgOut.Untag()[0] = CBORObject.FromObject(protect.EncodeToBytes());
                    }
                    break;

                case "ChangeProtected":
                    msgOut.Untag()[0] = CBORObject.FromObject(FromHex(failures["ChangeProtected"].AsString()));
                    break;

                case "RemoveCBORTag":
                    msgOut = msgOut.Untag();
                    break;

                case "RemoveProtected": {
                        CBORObject protect = CBORObject.DecodeFromBytes(msgOut.Untag()[0].GetByteString());
                        CBORObject mapRemove = CBORObject.NewMap();
                        AddAttributes(mapRemove, failures[failure.AsString()]);
                        foreach (CBORObject removeKey in mapRemove.Keys) {
                            protect.Remove(removeKey);
                        }
                        msgOut.Untag()[0] = CBORObject.FromObject(protect.EncodeToBytes());
                    }
                    break;

                default:
                    throw new Exception("Unknown failure string " + failure.AsString());
                }
            }
            return msgOut;
        }
#endif

        static CBORObject GetAttribute(CBORObject obj, string attrName)
        {
            if (obj.ContainsKey("protected") && obj["protected"].ContainsKey(attrName)) return obj["protected"][attrName];
            if (obj.ContainsKey("unprotected") && obj["unprotected"].ContainsKey(attrName)) return obj["unprotected"][attrName];
            if (obj.ContainsKey("unsent") && obj["unsent"].ContainsKey(attrName)) return obj["unsent"][attrName];
            return null;
        }

        static void AddAttributes(Attributes msg, CBORObject items, int destination)
        {
            _AddAttributes(msg, null, items, destination);
        }

        static void _AddAttributes(Attributes msg, CBORObject map, CBORObject items, int destination)
        {
            foreach (CBORObject cborKey2 in items.Keys) {
                CBORObject cborValue = items[cborKey2];
                CBORObject cborKey = cborKey2;
                string strKey = cborKey.AsString();

                if ((strKey.Length > 4) && (strKey.Substring(strKey.Length - 4, 4) == "_hex")) {
                    cborKey = CBORObject.FromObject(strKey.Substring(0, strKey.Length - 4));
                    cborValue = CBORObject.FromObject(FromHex(cborValue.AsString()));
                }

                switch (cborKey.AsString()) {
                case "alg":
                    cborKey = HeaderKeys.Algorithm;
                    cborValue = AlgorithmMap(cborValue);
                    break;

                case "kid":
                    cborKey = HeaderKeys.KeyId;
                    binFromText:
                    if (cborValue.Type == CBORType.TextString) cborValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cborValue.AsString()));
                    break;

                case "epk":
                    cborKey = HeaderKeys.EphemeralKey;
                    break;

                case "spk":
                    cborKey = CoseKeyParameterKeys.ECDH_StaticKey;
                    cborValue = GetKey(cborValue).EncodeToCBORObject();
                    break;

                case "salt": cborKey = CoseKeyParameterKeys.HKDF_Salt; goto binFromText;
                case "apu_id": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyU_ID; goto binFromText;
                case "apv_id": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyV_ID; goto binFromText;
                case "apu_nonce": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyU_nonce; goto binFromText;
                case "apv_nonce": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyV_nonce; goto binFromText;
                case "apu_other": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyU_Other; goto binFromText;
                case "apv_other": cborKey = CoseKeyParameterKeys.HKDF_Context_PartyV_Other; goto binFromText;
                case "pub_other": cborKey = CoseKeyParameterKeys.HKDF_SuppPub_Other; goto binFromText;
                case "priv_other": cborKey = CoseKeyParameterKeys.HKDF_SuppPriv_Other; goto binFromText;
                case "spk_kid": cborKey = CoseKeyParameterKeys.ECDH_StaticKey_kid; goto binFromText;

                case "IV": cborKey = HeaderKeys.IV; goto binFromText;
                case "partialIV": cborKey = HeaderKeys.PartialIV; goto binFromText;
#if false
                    if (cborValue.Type == CBORType.TextString) {
                        cborValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(cborValue.AsString()));
                    }
                    if (cborValue.Type == CBORType.ByteString) {
                        byte[] bytes = cborValue.GetByteString();
                        if (bytes.Length != 2) throw new Exception("Incorrect size for bytes->int");
                        cborValue = CBORObject.FromObject(bytes[0] * 256 + bytes[1]);
                    }
                    break;
#endif

                case "crit":
                    cborKey = HeaderKeys.Critical;

                    break;

                case "op time":
                    cborKey = HeaderKeys.OperationTime; {
                        DateTime when = DateTime.Parse(cborValue.AsString());
                        cborValue = CBORObject.FromObject((long) (when - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);

                    }
                    break;

                case "ctyp":
                    cborKey = HeaderKeys.ContentType;
                    break;

                default:
                    break;
                }

                switch (destination) {
                case 0: msg.AddAttribute(cborKey, cborValue, Attributes.PROTECTED); break;
                case 1: msg.AddAttribute(cborKey, cborValue, Attributes.UNPROTECTED); break;
                case 2: msg.AddAttribute(cborKey, cborValue, Attributes.DO_NOT_SEND); break;
                case 4: map[cborKey] = cborValue; break;
                }
            }
        }

        static void AddAttributes(CBORObject obj, CBORObject items)
        {
            _AddAttributes(null, obj, items, 4);
        }

        static void AddAttributes(JOSE.Attributes msg, CBORObject items, bool fProtected)
        {
            foreach (CBORObject key in items.Keys) {
                if ((key.AsString().Length > 4) && (key.AsString().Substring(key.AsString().Length - 4, 4) == "_hex")) {
                    msg.AddAttribute(key.AsString().Substring(0, key.AsString().Length - 4), JOSE.Message.base64urlencode(FromHex(items[key].AsString())), fProtected);
                }
                else msg.AddAttribute(key.AsString(), items[key].AsString(), fProtected);
            }
        }

        static void AddExternalData(Message msg, CBORObject externData)
        {
            msg.SetExternalData(FromHex(externData.AsString()));
        }

        static void AddExternalData(Recipient msg, CBORObject externData)
        {
            msg.SetExternalData(FromHex(externData.AsString()));
        }

        static void AddExternalData(Signer msg, CBORObject externData)
        {
            msg.SetExternalData(FromHex(externData.AsString()));
        }

        static void AddCounterSignature(Message msg, CBORObject items)
        {
            if (items.Type == CBORType.Map) {
                if ((!items.ContainsKey("signers")) || (items["signers"].Type != CBORType.Array)) throw new Exception("Missing or malformed counter signatures");
                foreach (CBORObject recip in items["signers"].Values) {
                    msg.AddCounterSignature(GetSigner(recip, true));
                }
            }
        }

        static Recipient GetRecipient(CBORObject control)
        {
            CBORObject alg = GetAttribute(control, "alg");

            Key key = null;

            if (control["key"] != null) key = GetKey(control["key"]);

            alg = AlgorithmMap(CBORObject.FromObject(alg.AsString()));
            Recipient recipient = new Recipient(key, alg);

            if (control.ContainsKey("alg")) {
                control.Remove(CBORObject.FromObject("alg"));
            }


            //  Double check that alg is the same as in the attributes

            if (control.ContainsKey("protected")) AddAttributes(recipient, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(recipient, control["unprotected"], 1);
            if (control.ContainsKey("unsent")) AddAttributes(recipient, control["unsent"], 2);
            if (control.ContainsKey("external")) AddExternalData(recipient, control["external"]);

            if (control.ContainsKey("recipients")) {
                if ((!control.ContainsKey("recipients")) || (control["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
                foreach (CBORObject recip in control["recipients"].Values) {
                    recipient.AddRecipient(GetRecipient(recip));
                }
            }

            if (control.ContainsKey("sender_key")) {
                Key myKey = GetKey(control["sender_key"]);
                recipient.SetSenderKey(myKey);
                if (myKey.ContainsName(CoseKeyKeys.KeyIdentifier)) {
                    recipient.AddAttribute(HeaderKeys.StaticKey_ID, CBORObject.FromObject(myKey.AsBytes(CoseKeyKeys.KeyIdentifier)), Attributes.UNPROTECTED);
                }
                else {
                    recipient.AddAttribute(HeaderKeys.StaticKey, myKey.PublicKey().AsCBOR(), Attributes.UNPROTECTED);
                }
            }
            return recipient;
        }

        static JOSE.Recipient GetRecipientJOSE(CBORObject control)
        {
            JOSE.Key key;

            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            if (control.ContainsKey("key")) {
                key = new JOSE.Key(JOSE.JSON.Parse(control["key"].ToJSONString()));
            }
            else if (control.ContainsKey("pwd")) {
                key = new JOSE.Key();
                key.Add("kty", "oct");
                key.Add("k", JOSE.Message.base64urlencode(UTF8Encoding.UTF8.GetBytes(control["pwd"].AsString())));
            }
            else throw new Exception("No key defined for a recipient");

            JOSE.Recipient recipient = new JOSE.Recipient(key, control["alg"].AsString());

            //  Double check that alg is the same as in the attributes

            recipient.ClearProtected();
            recipient.ClearUnprotected();

            if (control.ContainsKey("protected_jose")) AddAttributes(recipient, control["protected_jose"], true);
            if (control.ContainsKey("unprotected_jose")) AddAttributes(recipient, control["unprotected_jose"], false);

            if (control.ContainsKey("sender_key")) {
                JOSE.Key myKey = new JOSE.Key(JOSE.JSON.Parse(control["sender_key"].ToJSONString()));
                recipient.SetSenderKey(myKey);
            }
            return recipient;
        }

        static Signer GetSigner(CBORObject control, bool fCounterSign = false)
        {
            CBORObject alg = GetAttribute(control, "alg");
            if (control.ContainsKey("alg")) {
                control.Remove(CBORObject.FromObject("alg"));
            }

            Key key = GetKey(control["key"]);

            Signer signer;

            if (fCounterSign) signer = new CounterSignature(key, alg);
            else signer = new Signer(key, control["alg"]);

            if (control.ContainsKey("protected")) AddAttributes(signer, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(signer, control["unprotected"], 1);
            if (control.ContainsKey("unsent")) AddAttributes(signer, control["unsent"], 2);
            if (control.ContainsKey("external")) signer.SetExternalData(FromHex(control["external"].AsString()));

            return signer;
        }

        static JOSE.Signer GetSignerJOSE(CBORObject control)
        {
            if (!control.ContainsKey("alg")) throw new Exception("Signer missing alg field");

            JOSE.Key key = new JOSE.Key(JOSE.JSON.Parse(control["key"].ToJSONString()));

            JOSE.Signer signer = new JOSE.Signer(key, control["alg"].AsString());

            if (control.ContainsKey("protected_jose")) AddAttributes(signer, control["protected_jose"], true);
            if (control.ContainsKey("unprotected_jose")) AddAttributes(signer, control["unprotected_jose"], false);

            return signer;
        }

        static Key GetKey(CBORObject control, bool fPublicKey = false)
        {
            Key key = new Key();
            CBORObject newKey;
            CBORObject newValue;
            string type = control["kty"].AsString();
            int oFix = 0;
            List<string> keys = new List<string>();

            foreach (CBORObject item in control.Keys) keys.Add(item.AsString());

            foreach (string item in keys) {
                switch (item) {
                case "kty":
                    newKey = CoseKeyKeys.KeyType;
                    switch (control[item].AsString()) {
                    case "OKP": newValue = GeneralValues.KeyType_OKP; goto NewValue;
                    case "EC": newValue = GeneralValues.KeyType_EC; goto NewValue;
                    case "RSA": newValue = GeneralValues.KeyType_RSA; goto NewValue;
                    case "oct": newValue = GeneralValues.KeyType_Octet; goto NewValue;
                    default:
                        break;
                    }
                    TextValue:
                    key.Add(newKey, control[item]);
                    break;

                case "kid":
                    newKey = CoseKeyKeys.KeyIdentifier;
                    newValue = CBORObject.FromObject(UTF8Encoding.UTF8.GetBytes(control[item].AsString()));
                    goto NewValue;

                case "kid_hex":
                    newKey = CoseKeyKeys.KeyIdentifier;
                    BinaryValue:
                    if (oFix != 0) {
                        byte[] v = base64urldecode(control[item].AsString());
                        if (v.Length != oFix) {
                            byte[] y = new byte[oFix];
                            Array.Copy(v, 0, y, oFix - v.Length, v.Length);
                            control[item] = CBORObject.FromObject(base64urlencode(y));
                            v = y;
                        }
                        key.Add(newKey, CBORObject.FromObject(v));
                    }
                    else {
                        key.Add(newKey, CBORObject.FromObject(base64urldecode(control[item].AsString())));
                    }
                    break;

                case "alg":
                    newKey = CoseKeyKeys.Algorithm;
                    goto TextValue;

                // ECDSA parameters
                case "crv":
                    newKey = CoseKeyParameterKeys.EC_Curve;
                    switch (control[item].AsString()) {
                    case "P-256":
                        newValue = GeneralValues.P256;
                        break;

                    case "P-384":
                        newValue = GeneralValues.P384;
                        break;

                    case "P-521":
                        newValue = GeneralValues.P521;
                        oFix = 66;
                        break;

                    case "X25519":
                        newValue = GeneralValues.X25519;
                        break;

                    default:
                        newValue = control[item];
                        break;
                    }
                    NewValue:
                    key.Add(newKey, newValue);
                    break;

                case "use":
                    break;

                case "enc":
                    key.Add(CBORObject.FromObject(item), control[item]);
                    break;

                case "x":
                    if (type == "OKP") newKey = CoseKeyParameterKeys.OKP_X;
                    else newKey = CoseKeyParameterKeys.EC_X;
                    goto BinaryValue;

                case "y": newKey = CoseKeyParameterKeys.EC_Y; goto BinaryValue;

                case "e": newKey = CoseKeyParameterKeys.RSA_e; goto BinaryValue;
                case "n": newKey = CoseKeyParameterKeys.RSA_n; goto BinaryValue;

                case "d":
                    // if (!fPublicKey) continue;
                    if (type == "RSA") newKey = CoseKeyParameterKeys.RSA_d;
                    else if (type == "OKP") newKey = CoseKeyParameterKeys.OKP_D;
                    else newKey = CoseKeyParameterKeys.EC_D;
                    goto BinaryValue;

                case "k": newKey = CoseKeyParameterKeys.Octet_k; goto BinaryValue;
                case "p": newKey = CoseKeyParameterKeys.RSA_p; goto BinaryValue;
                case "q": newKey = CoseKeyParameterKeys.RSA_q; goto BinaryValue;
                case "dp": newKey = CoseKeyParameterKeys.RSA_dP; goto BinaryValue;
                case "dq": newKey = CoseKeyParameterKeys.RSA_dQ; goto BinaryValue;
                case "qi": newKey = CoseKeyParameterKeys.RSA_qInv; goto BinaryValue;

                default:
                    throw new Exception("Unrecognized field name " + item + " in key object");
                }
            }

            allkeys.AddKey(key);

            Key pubKey = key.PublicKey();
            if (pubKey != null) {
                allPubKeys.AddKey(key.PublicKey());
            }
            return key;
        }

        static string base64urlencode(byte[] rgb)
        {
            string s = Convert.ToBase64String(rgb);
            s = s.Replace('+', '-');
            s = s.Replace('/', '_');
            s = s.Replace("=", "");
            return s;
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

        public static string ToHex(byte[] rgb)
        {
            string hex = BitConverter.ToString(rgb);
            return hex.Replace("-", "");
        }

        public static byte[] FromHex(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        public static CBORObject AsCbor(JOSE.JSON json)
        {
            CBORObject obj;

            switch (json.nodeType) {
            case JOSE.JsonType.array:
                obj = CBORObject.NewArray();
                foreach (JOSE.JSON pair in json.array) {
                    obj.Add(AsCbor(pair));
                }
                return obj;

            case JOSE.JsonType.map:
                obj = CBORObject.NewMap();
                foreach (KeyValuePair<string, JOSE.JSON> pair in json.map) {
                    obj.Add(pair.Key, AsCbor(pair.Value));
                }
                return obj;

            case JOSE.JsonType.number:
                return CBORObject.FromObject(json.number);

            case JOSE.JsonType.text:
                return CBORObject.FromObject(json.text);

            case JOSE.JsonType.unknown:
            default:
                throw new Exception("Can deal with unknown JSON node type");
            }


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
            case "RSA-OAEP": return AlgorithmValues.RSA_OAEP;
            case "RSA-OAEP-256": return AlgorithmValues.RSA_OAEP_256;
            case "HS256": return AlgorithmValues.HMAC_SHA_256;
            case "HS256/64": return AlgorithmValues.HMAC_SHA_256_64;
            case "HS384": return AlgorithmValues.HMAC_SHA_384;
            case "HS512": return AlgorithmValues.HMAC_SHA_512;
            case "ES256": return AlgorithmValues.ECDSA_256;
            case "ES384": return AlgorithmValues.ECDSA_384;
            case "ES512": return AlgorithmValues.ECDSA_512;
            case "PS256": return AlgorithmValues.RSA_PSS_256;
            case "PS512": return AlgorithmValues.RSA_PSS_512;
            case "direct": return AlgorithmValues.Direct;
            case "AES-CMAC-128/64": return AlgorithmValues.AES_CMAC_128_64;
            case "AES-CMAC-256/64": return AlgorithmValues.AES_CMAC_256_64;
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
            case "ChaCha-Poly1305": return AlgorithmValues.ChaCha20_Poly1305;
            default: return old;
            }
        }

        static int GetKeySize(CBORObject alg)
        {
            int cbitKey = -1;

            if (alg.Type == CBORType.TextString) {
                switch (alg.AsString()) {

                case "AES-CCM-128/64":
                case "AES-CMAC-128/64":
                    cbitKey = 128;
                    break;

                case "AES-CMAC-256/64":
                    cbitKey = 256;
                    break;

                case "HS384":
                    cbitKey = 384;
                    break;

                default:
                    throw new Exception("NYI");
                }
            }
            else if (alg.Type == CBORType.Number) {
                switch ((AlgorithmValuesInt) alg.AsInt32()) {
                case AlgorithmValuesInt.AES_GCM_128:
                case AlgorithmValuesInt.AES_CCM_16_64_128:
                case AlgorithmValuesInt.AES_CCM_64_64_128:
                case AlgorithmValuesInt.AES_CCM_16_128_128:
                case AlgorithmValuesInt.AES_CCM_64_128_128:
                case AlgorithmValuesInt.AES_KW_128:
                    cbitKey = 128;
                    break;

                case AlgorithmValuesInt.AES_GCM_192:
                case AlgorithmValuesInt.AES_KW_192:
                    cbitKey = 192;
                    break;

                case AlgorithmValuesInt.AES_GCM_256:
                case AlgorithmValuesInt.AES_CCM_16_64_256:
                case AlgorithmValuesInt.AES_CCM_64_64_256:
                case AlgorithmValuesInt.AES_CCM_16_128_256:
                case AlgorithmValuesInt.AES_CCM_64_128_256:
                case AlgorithmValuesInt.AES_KW_256:
                case AlgorithmValuesInt.HMAC_SHA_256:
                    cbitKey = 256;
                    break;

                case AlgorithmValuesInt.HMAC_SHA_512:
                    cbitKey = 512;
                    break;

                default:
                    throw new Exception("NYI");
                }
            }
            else throw new Exception("Algorithm incorrectly encoded");

            return cbitKey;
        }

        static CBORObject GetSection(CBORObject control, string tag)
        {
            CBORObject obj;

            if (control.ContainsKey(tag)) return control[tag];

            obj = CBORObject.NewMap();
            control.Add(tag, obj);
            return obj;
        }

        static void SetField(CBORObject obj, string tag, byte[] value, ref bool fDirty)
        {
            if (obj.ContainsKey(tag)) {
                if (value == null) {
                    obj.Remove(CBORObject.FromObject(tag));
                    fDirty = true;
                    return;
                }
                string old = obj[tag].AsString();
                string newVal = ToHex(value);
                if (old != newVal) {
                    obj[tag] = CBORObject.FromObject(newVal);
                    fDirty = true;
                }
            }
            else if (value != null) {
                obj.Add(tag, CBORObject.FromObject(ToHex(value)));
                fDirty = true;
            }
        }


        static void ValidateJSON(CBORObject control)
        {
            bool result = false;

            try {

                if (control["input"].ContainsKey("mac")) result = ValidateMAC(control);
                else if (control["input"].ContainsKey("enveloped")) result = ValidateEnveloped(control);
                else if (control["input"].ContainsKey("mac0")) result = ValidateMac0(control);
                else if (control["input"].ContainsKey("encrypted")) result = ValidateEncrypted(control);
                else if (control["input"].ContainsKey("sign")) result = ValidateSigned(control);
                else if (control["input"].ContainsKey("sign0")) result = ValidateSign0(control);
                else throw new Exception("Unknown operation in control");

                if (!result) {
                    Console.Write(" ");
                }
            }
            catch (CoseException e) {
                Console.WriteLine();
                Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
            }
            catch (JOSE.JOSE_Exception e) {
                Console.WriteLine();
                Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
            }
            catch (Exception e) {
                Console.WriteLine();
                throw e;
            }
            Console.WriteLine(result ? ".... PASS" : ".... FAILED");
        }

        static bool ValidateEnveloped(CBORObject control)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["enveloped"];
            byte[] rgb = FromHex(control["output"]["cbor"].AsString());

            if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");
            for (int iRecipient = 0; iRecipient < encrypt["recipients"].Count; iRecipient++) {

                bool fFail = HasFailMarker(control) || HasFailMarker(encrypt);
                EncryptMessage msg;

                try {

                    Message msgX = Message.DecodeFromBytes(rgb, Tags.Enveloped);
                    msg = (EncryptMessage) msgX;
                }
                catch(Exception) {
                    if (fFail) return true;
                    return false;
                }

                if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);
                if (encrypt.ContainsKey("external")) AddExternalData(msg, encrypt["external"]);

                CBORObject recip = encrypt["recipients"][iRecipient];
                Recipient recipX = msg.RecipientList[iRecipient];

                recipX = SetRecievingAttributes(recipX, recip);

                if (recip["sender_key"] != null) {
                    if (recipX.FindAttribute(HeaderKeys.StaticKey) == null) {
                        recipX.AddAttribute(HeaderKeys.StaticKey, GetKey(recip["sender_key"], true).AsCBOR(), Attributes.DO_NOT_SEND);
                    }
                }

                bool fFailRecipient = HasFailMarker(recip);

                try {
                    msg.Decrypt(recipX);
                    
                }
                catch (Exception) {
                    if (fFail || fFailRecipient) return true;
                    return false;
                }
            }

            return true;
        }

        static bool ValidateMAC(CBORObject control)
        {
            CBORObject input = control["input"];
            CBORObject mac = input["mac"];
            byte[] rgb = FromHex(control["output"]["cbor"].AsString());
            bool f = true;

            if ((!mac.ContainsKey("recipients")) || (mac["recipients"].Type != CBORType.Array)) throw new Exception("Missing or malformed recipients");

            for (int iRecipient = 0; iRecipient < mac["recipients"].Count; iRecipient++) {
                CBORObject recip = mac["recipients"][iRecipient];
                MACMessage msg;

                bool fFail = HasFailMarker(mac) || HasFailMarker(control);

                try {
                    Message msgX = Message.DecodeFromBytes(rgb, Tags.MAC);
                    msg = (MACMessage) msgX;
                }
                catch (CoseException) {
                    // Check for expected decode failure
                    if (fFail) return true;
                    return false;
                }

                bool fFailRecip = HasFailMarker(recip);

                SetRecievingAttributes(msg, mac);

                Recipient recipX = msg.RecipientList[iRecipient];
                Key key = GetKey(recip["key"], false);
                recipX.SetKey(key);

                recipX = SetRecievingAttributes(recipX, recip);

                CBORObject cnStatic = recip["sender_key"];
                if (cnStatic != null) {
                    if (recipX.FindAttribute(HeaderKeys.StaticKey) == null) {
                        recipX.AddAttribute(HeaderKeys.StaticKey, GetKey(cnStatic, true).AsCBOR(), Attributes.DO_NOT_SEND);
                    }
                }

                try {
                    f = msg.Validate(recipX);
                    if (f && (fFail || fFailRecip)) return false;
                    else if (!f && !(fFail || fFailRecip)) return false;
                }
                catch (Exception) {
                    if (!(fFail || fFailRecip)) return false;
                }
            }

            return true;

        }

        static bool ValidateSigned(CBORObject cnControl)
        {
            CBORObject cnInput = cnControl["input"];
            CBORObject cnMessage;
            CBORObject cnSigners;
            bool fFailBody = false;

            fFailBody = HasFailMarker(cnControl);

            try {
                cnMessage = cnInput["sign"];
                cnSigners = cnMessage["signers"];
                byte[] rgb = FromHex(cnControl["output"]["cbor"].AsString());
                int i = 0;
                foreach (CBORObject cnSigner in cnSigners.Values) {
                    SignMessage signMsg = null;

                    try {
                        Message msg = Message.DecodeFromBytes(rgb, Tags.Signed);
                        signMsg = (SignMessage) msg;
                    }
                    catch (Exception e) {
                        if (fFailBody) return true;
                        throw e;
                    }

                    SetRecievingAttributes(signMsg, cnMessage);

                    Key cnKey = GetKey(cnSigner["key"]);
                    Signer hSigner = signMsg.SignerList[i];

                    SetRecievingAttributes(hSigner, cnSigner);

                    hSigner.SetKey(cnKey);

                    Boolean fFailSigner = HasFailMarker(cnSigner);

                    try {
                        Boolean f = signMsg.Validate(hSigner);
                        if (!f && !(fFailBody || fFailSigner)) return false;
                    }
                    catch (Exception) {
                        if (!fFailBody && !fFailSigner) return false;
                    }

                    CBORObject cnCounter;
                    if (i == 0) {
                        cnCounter = cnMessage["countersign"];
                        if (cnCounter != null) {
                            CheckCounterSignatures(signMsg, cnMessage);
                        }
                    }
#if false
                    cnCounter = cnSigner["countersign"];
                    if (cnCounter != null) {
                        CheckCounterSignatures(hSigner, cnSigner);
                    }
#endif
                    i++;
                }
            }
            catch (Exception) {
                return false;
            }
            return true;
        }

        static public Boolean HasFailMarker(CBORObject cn)
        {
            CBORObject cnFail = cn["fail"];
            if (cnFail != null && cnFail.AsBoolean()) return true;
            return false;
        }

        static Recipient SetRecievingAttributes(Recipient recip, CBORObject control)
        {
            Key key = null;

            if (control.ContainsKey("unsent")) AddAttributes(recip, control["unsent"], 2);

            if (control.ContainsKey("external")) AddExternalData(recip, control["external"]);

            if (control["key"] != null) key = GetKey(control["key"]);

            recip.SetKey(key);

            return recip;
        }

        static void SetRecievingAttributes(Message recip, CBORObject control)
        {
            if (control.ContainsKey("unsent")) AddAttributes(recip, control["unsent"], 2);

            if (control.ContainsKey("external")) AddExternalData(recip, control["external"]);
        }

        static void SetRecievingAttributes(Signer recip, CBORObject control)
        {
            if (control.ContainsKey("unsent")) AddAttributes(recip, control["unsent"], 2);

            if (control.ContainsKey("external")) AddExternalData(recip, control["external"]);
        }

        static void CheckCounterSignatures(Message msg, CBORObject cSigInfo)
        {
            CBORObject cSigs = msg.FindAttribute(HeaderKeys.CounterSignature);

            if (cSigs == null) throw new Exception("No counter signature found");

            if (cSigs.Type != CBORType.Array) throw new Exception("Incorrect counter sign object");

            CBORObject cSigConfig = cSigInfo["signers"];

#if false
            int iCSign;
            for (iCSign = 0; iCSign < cSigConfig.Count; iCSign++) {
                CounterSignature sig;
                if (cSigs[0].Type != CBORType.Array) {
                    sig = new CounterSignature();
                    sig.DecodeFromCBORObject(cSigs);
                }
                else {
                    sig = new CounterSignature();
                    sig.DecodeFromCBORObject(cSigs[iCSign]);
                }

                CBORObject cnKey = BuildKey(cSigConfig[iCSign]["key"], false);
                SetReceivingAttributes(sig, cSigConfig[iCSign]);

                sig.setKey(cnKey);

                Boolean f = sig.Validate(msg);
            }
#endif
        }
    }

    class BadOutputException : Exception
    {
        public BadOutputException() : base("Output selection not supported for this input set") { }
    }
}
