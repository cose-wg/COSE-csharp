using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Linq.Expressions;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars;
using Com.AugustCellars.JOSE;
using Org.BouncyCastle.Crypto.Digests;
using PeterO.Cbor;


namespace examples
{
    public class JoseExamples
    {
        static string RootDir = @"d:\Projects\JOSE\cookbook";

        public void RunJoseExamples()
        {
            RunTestsInDirectory(RootDir + "\\jwe");
        }

        public static void RunTestsInDirectory(string strDirectory)
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
                    if (di.Name[0] == '.') continue;
                    ProcessFile(strDirectory, di.Name);
                }
            }
        }

#if false
        public static void RunTests(string directory)
        {
            DirectoryInfo diTop;

            if (false) {
                Console.WriteLine("ProcessFile: ");
                ProcessNestedFile(Path.Combine(directory, @"6.nesting_signatures_and_encryption.json"));

                //      PBE_Tests();

                diTop = new DirectoryInfo(@"c:\Projects\JOSE\test\jwe");


                foreach (var fi in diTop.EnumerateFiles()) {
                    Console.WriteLine("Process file: " + fi.Name);
                    ProcessFile(fi.FullName);
                }


                diTop = new DirectoryInfo(@"c:\projects\JOSE\test\jws");
                foreach (var fi in diTop.EnumerateFiles()) {
                    Console.WriteLine("Process file: " + fi.Name);
                    ProcessFile(fi.FullName);

                }
            }
            diTop = new DirectoryInfo(@"c:\projects\JOSE\test\jws-2");
            foreach (var fi in diTop.EnumerateFiles()) {
                Console.WriteLine("Process file: " + fi.Name);
                ProcessFile(fi.FullName);
            }
            diTop = new DirectoryInfo(@"c:\projects\JOSE\test\eddsa");
            foreach (var fi in diTop.EnumerateFiles()) {
                Console.WriteLine("Process file: " + fi.Name);
                ProcessFile(fi.FullName);
            }

        }
#endif

        static void ProcessFile(string dir, string fileName)
        {
            StreamReader file = File.OpenText(Path.Combine(RootDir, dir, fileName));
            string fileText = file.ReadToEnd();
            file.Close();
            file.Dispose();
            CBORObject control = CBORObject.FromJSONString(fileText);

            Directory.CreateDirectory(RootDir + "\\new\\" + dir);

            try {
                if (ProcessJSON(control)) {
                    fileText = control.ToJSONString();
                    JSON j = JSON.Parse(fileText);
                    fileText = j.Serialize(0);
                    StreamWriter file2 = File.CreateText(RootDir + "\\new\\" + dir + "\\" + fileName);
                    file2.Write(fileText);
                    file2.Write("\r\n");
                    file2.Close();
                }

                ValidateJSON(control);
            }
            catch (Exception e) {
                Console.WriteLine($"ERROR: {e}");
            }
        }

        static void ValidateJSON(CBORObject control)
        {
            bool result = false;

            try {
                if (control["input"].ContainsKey("enveloped")) {
                    result = ValidateEnveloped(control);
                }
                else if (control["input"].ContainsKey("sign")) {
                   result = ValidateSigned(control);
                }
                else {
                    throw new Exception("Unknown operation in control");
                }

                if (!result) {
                    Console.Write(" ");
                }
            }
            catch (JoseException e) {
                Console.WriteLine();
                Console.WriteLine(String.Format("COSE threw an error '{0}'.", e.ToString()));
            }
            catch (Exception e) {
                Console.WriteLine();
                throw e;
            }

            Console.WriteLine(result ? ".... PASS" : ".... FAILED");
        }

        private static string[] Formats = {"json", "json_flat", "compact"};



        static bool ProcessJSON(CBORObject control)
        {
            bool modified = false;
            StaticPrng prng = new StaticPrng();

            if (control.ContainsKey("title")) {
                Console.Write("Processing: " + control["title"].AsString());
            }

            if (control["input"].ContainsKey("rng_stream")) {
                if (control["input"]["rng_stream"].Type == CBORType.TextString) {
                    prng.AddSeedMaterial(Program.FromHex(control["input"]["rng_stream"].AsString()));
                }
                else if (control["input"]["rng_stream"].Type == CBORType.Array) {
                    foreach (var x in control["input"]["rng_stream"].Values) {
                        prng.AddSeedMaterial(Program.FromHex(x.AsString()));
                    }
                }
            }

            Message.SetPRNG(prng);

            try {

                prng.Reset();
                Message result;


                if (control["input"].ContainsKey("enveloped")) result = ProcessEnveloped(control, ref modified);
                else if (control["input"].ContainsKey("sign")) result = ProcessSign(control, ref modified);
                else throw new Exception("Unknown operation in control");

                foreach (string format in Formats) {
                    CBORObject json = null;
                    string jsonText = null;

                    try {
                        switch (format) {
                        case "json":
                            json = result.EncodeToJSON(false);
                            break;

                        case "json_flat":
                            json = result.EncodeToJSON(true);
                            break;

                        case "compact":
                            jsonText = result.EncodeCompressed();
                            break;
                        }
                    }
                    catch (JoseException) {
                        // Ignore
                    }


                    if (control["output"].ContainsKey(format)) {
                        if (json == null && jsonText == null) {
                            control["output"].Remove(format);
                            modified = true;
                        }
                        else {

                            CBORObject oldVersion = control["output"][format];

                            if (format == "compact") {
                                if (oldVersion.Type != CBORType.TextString || jsonText != oldVersion.AsString()) {
                                    Console.WriteLine();
                                    Console.WriteLine($"******************* New and Old do not match {format}!!!");
                                    Console.WriteLine();

                                    control["output"][format] = CBORObject.FromObject(jsonText);
                                    modified = true;
                                }
                            }
                            else if (json.ToJSONString() != oldVersion.ToJSONString()) {
                                Console.WriteLine();
                                Console.WriteLine($"******************* New and Old do not match {format}!!!");
                                Console.WriteLine();

                                control["output"][format] = json;
                                modified = true;
                            }
                        }
                    }
                    else {
                        if (format == "compact" && jsonText != null) {
                            control["output"].Add(format, jsonText);
                            modified = true;
                        }
                        else if (json != null) {
                            control["output"].Add(format, json);
                            modified = true;
                        }
                    }
                }


                if (prng.IsDirty) {
                    if (prng.Buffer != null) {
                        if (control["input"].ContainsKey("rng_stream")) {
                            control["input"]["rng_stream"] = prng.Buffer;
                        }
                        else {
                            control["input"].Add("rng_stream", prng.Buffer);
                        }
                    }
                    else {
                        if (control["input"].ContainsKey("rng_stream")) {
                            control["input"].Remove(CBORObject.FromObject("rng_stream"));
                        }
                    }

                    modified = true;
                }

            }
            catch (Com.AugustCellars.JOSE.JoseException e) {
                Console.WriteLine($"JOSE threw an error '{e}'.");
            }

            return modified;
        }

        static Message ProcessEnveloped(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["enveloped"];

            EncryptMessage msg = new EncryptMessage();

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (encrypt.ContainsKey("protected")) AddAttributes(msg, encrypt["protected"], 0);
            if (encrypt.ContainsKey("unprotected")) AddAttributes(msg, encrypt["unprotected"], 1);
            if (encrypt.ContainsKey("unsent")) AddAttributes(msg, encrypt["unsent"], 2);

            if (encrypt.ContainsKey("alg")) {
                encrypt.Remove(CBORObject.FromObject("alg"));
            }

            if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) {
                throw new Exception("Missing or malformed recipients");
            }

            foreach (CBORObject recipient in encrypt["recipients"].Values)
            {
                msg.AddRecipient(GetRecipient(recipient));
            }

            {
                msg.Encode();

                CBORObject intermediates = Program.GetSection(control, "intermediates");

//                SetField(intermediates, "AAD_hex", msg.getAADBytes(), ref fDirty);
//                SetField(intermediates, "CEK_hex", msg.getCEK(), ref fDirty);

                CBORObject rList = Program.GetSection(intermediates, "recipients");

//                SaveRecipientDebug(msg.RecipientList, rList, ref fDirty);
            }


#if false
            //  If we want this to fail, look at the different failure methods.
            if (input.ContainsKey("failures"))
            {
                msgOut = ProcessFailures(msgOut, input["failures"], 2);
            }
#endif

            return msg;
        }


        static bool ValidateEnveloped(CBORObject control)
        {
            CBORObject input = control["input"];
            CBORObject encrypt = input["enveloped"];

            if ((!encrypt.ContainsKey("recipients")) || (encrypt["recipients"].Type != CBORType.Array)) {
                throw new Exception("Missing or malformed recipients");
            }

            for (int iRecipient = 0; iRecipient < encrypt["recipients"].Count; iRecipient++) {

                bool fFail = HasFailMarker(control) || HasFailMarker(encrypt);
                EncryptMessage encryptMessage;

                try {

                    Message message;
                    CBORObject obj = control["output"]["json"];
                    if (obj.Type == CBORType.TextString) {
                        message = Message.DecodeFromString(obj.AsString());
                    }
                    else {
                        message = Message.DecodeFromJSON(obj);
                    }

                    encryptMessage = (EncryptMessage) message;
                }
                catch (Exception) {
                    if (fFail) return true;
                    return false;
                }

                if (encrypt.ContainsKey("unsent")) AddAttributes(encryptMessage, encrypt["unsent"], 2);
                CBORObject recipient = encrypt["recipients"][iRecipient];
                Recipient recipientMessage = encryptMessage.RecipientList[iRecipient];

                recipientMessage = SetReceivingAttributes(recipientMessage, recipient);

                /*
                if (recipient["sender_key"] != null)
                {
                    if (recipientMessage.FindAttribute(HeaderKeys.StaticKey) == null)
                    {
                        recipientMessage.AddAttribute(HeaderKeys.StaticKey, GetKey(recipient["sender_key"], true).AsCBOR(),
                            Attributes.DO_NOT_SEND);
                    }
                }
                */

                bool fFailRecipient = HasFailMarker(recipient);

                try {
                    encryptMessage.Decrypt(recipientMessage);

                    if (encryptMessage.GetContentAsString() != input["plaintext"].AsString()) {
                        return false;
                    }

                }
                catch (Exception) {
                    if (fFail || fFailRecipient) return true;
                    return false;
                }
            }


            return true;
        }


        static Message ProcessSign(CBORObject control, ref bool fDirty)
        {
            CBORObject input = control["input"];
            CBORObject sign = input["sign"];
            CBORObject signers;

            SignMessage msg = new SignMessage();

            if (!input.ContainsKey("plaintext")) throw new Exception("missing plaintext field");
            msg.SetContent(input["plaintext"].AsString());

            if (sign.ContainsKey("protected")) AddAttributes(msg, sign["protected"], 0);
            if (sign.ContainsKey("unprotected")) AddAttributes(msg, sign["unprotected"], 1);
            if (sign.ContainsKey("unsent")) AddAttributes(msg, sign["unsent"], 2);

            if ((!sign.ContainsKey("signers")) || (sign["signers"].Type != CBORType.Array))
                throw new Exception("Missing or malformed recipients");
            foreach (CBORObject recip in sign["signers"].Values)
            {
                msg.AddSigner(GetSigner(recip));
            }

            {
                msg.Encode();

                signers = Program.GetSection(Program.GetSection(control, "intermediates"), "signers", CBORType.Array);
                

                for (int iSigner = 0; iSigner < msg.SignerList.Count; iSigner++)
                {
                    while (signers.Count < msg.SignerList.Count) {
                        signers.Add(CBORObject.NewMap());
                    }
                    
                    Program.SetField(signers[iSigner], "ToBeSign", msg.SignerList[iSigner].ToBeSigned, ref fDirty);
                }
            }

            return msg;
        }

        static bool ValidateSigned(CBORObject cnControl)
        {
            CBORObject cnInput = cnControl["input"];
            CBORObject cnMessage;
            CBORObject cnSigners;
            bool fFailBody = false;

            fFailBody = HasFailMarker(cnControl);

            try
            {
                cnMessage = cnInput["sign"];
                cnSigners = cnMessage["signers"];

                foreach (string format in Formats) {
                    if (!cnControl["output"].ContainsKey(format)) {
                        continue;
                    }

                    string rgb;
                    if (format == "compact") {
                        rgb = cnControl["output"][format].AsString();
                    }
                    else {
                        rgb = cnControl["output"][format].ToJSONString();
                    }

                    int i = 0;
                    foreach (CBORObject cnSigner in cnSigners.Values) {
                        SignMessage signMsg = null;

                        try {
                            Message msg = Message.DecodeFromString(rgb);
                            signMsg = (SignMessage) msg;
                        }
                        catch (Exception e) {
                            if (fFailBody) return true;
                            throw e;
                        }

                        // SetReceivingAttributes(signMsg, cnMessage);

                        JWK cnKey = GetKey(cnSigner["key"]);
                        Signer hSigner = signMsg.SignerList[i];

                        SetReceivingAttributes(hSigner, cnSigner);

                        hSigner.SetKey(cnKey);

                        bool fFailSigner = HasFailMarker(cnSigner);

                        try {
                            bool f = signMsg.Validate(hSigner);
                            if (!f && !(fFailBody || fFailSigner)) return false;
                        }
                        catch (Exception) {
                            if (!fFailBody && !fFailSigner) return false;
                        }

                        i++;
                    }
                }
            }
            catch (Exception)
            {
                return false;
            }

            return true;
        }


        static Signer GetSigner(CBORObject control)
        {
            CBORObject alg = GetAttribute(control, "alg");
            if (control.ContainsKey("alg"))
            {
                control.Remove(CBORObject.FromObject("alg"));
            }

            JWK key = GetKey(control["key"]);

            Signer signer;

                signer = new Signer(key, alg.AsString());

            if (control.ContainsKey("protected")) AddAttributes(signer, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(signer, control["unprotected"], 1);
            if (control.ContainsKey("unsent")) AddAttributes(signer, control["unsent"], 2);

            return signer;
        }

        static void ProcessNestedFile(string fileName)
        {
            StreamReader file = File.OpenText(fileName);

            string fileText = file.ReadToEnd();
            file.Close();

            CBORObject control = CBORObject.FromJSONString(fileText);

            ProcessJSON(control["sign"]);

            ProcessJSON(control["encrypt"]);

        }


#if false
        static void CheckMessage(Message msg, JWK key, CBORObject input)
        {
            if (msg.GetType() == typeof(EncryptMessage)) {
                EncryptMessage enc = (EncryptMessage) msg;

                Recipient recipient = enc.RecipientList[0];
                recipient.SetKey(key);

                try {
                    enc.Decrypt(recipient);
                }
                catch (Exception e) { Console.WriteLine("Failed to decrypt " + e.ToString()); return; }

                if (enc.GetContentAsString() != input["plaintext"].AsString()) Console.WriteLine("Plain text does not match");
            }
            else if (msg.GetType() == typeof(SignMessage)) {
                SignMessage sig = (SignMessage) msg;

                try {
                    try {
                        sig.GetContentAsString();
                    }
                    catch (System.Exception) {
                        sig.SetContent(input["payload"].AsString());
                    }
                    sig.Validate(key);

                    if (sig.GetContentAsString() != input["payload"].AsString()) Console.WriteLine("Plain text does not match");
                }
                catch (Exception e) { Console.WriteLine("Failed to verify " + e.ToString()); return; }
            }
        }
#endif

#if false
        static void BuildCompact(CBORObject control, JwkSet keys)
        {
            //  Encrypted or Signed?
            if (control.ContainsKey("signing")) {
                SignMessage sign = new SignMessage();
                Signer signer = new Signer(keys[0]);

                sign.SetContent(control["input"]["payload"].AsString());
                sign.AddSigner(signer);

                CBORObject xx = control["signing"]["protected"];
                foreach (CBORObject key in xx.Keys) {
                    signer.AddAttribute(key, xx[key], Attributes.PROTECTED);
                }

                string output = sign.EncodeCompressed();

                Message msg = Message.DecodeFromString(output);

                CheckMessage(msg, keys[0], control["input"]);

            }
            else if (control.ContainsKey("encrypting_key")) {
                EncryptMessage enc = new EncryptMessage();
                CBORObject xx = control["encrypting_content"]["protected"];
                foreach (CBORObject key in xx.Keys) {
                    enc.AddAttribute(key, xx[key], Attributes.PROTECTED);
                }

                Recipient recip = new Recipient(keys[0], control["input"]["alg"].AsString(), enc);

                enc.AddRecipient(recip);
                enc.SetContent(control["input"]["plaintext"].AsString());

                string output = enc.EncodeCompressed();

                Message msg = Message.DecodeFromString(output);

                CheckMessage(msg, keys[0], control["input"]);

            }
        }
#endif

        static void PBE_Tests()
        {
            byte[] password = UTF8Encoding.ASCII.GetBytes("password");
            byte[] salt = Encoding.ASCII.GetBytes("salt");

            byte[] output = Recipient.PBKDF2(password, salt, 1, 20, new Sha1Digest());

        }

        static void ProcessPassport(JSON control)
        {

        }


        static void AddAttributes(Attributes msg, CBORObject items, int destination)
        {
            _AddAttributes(msg, null, items, destination);
        }

        static void _AddAttributes(Attributes msg, CBORObject map, CBORObject items, int destination)
        {
            foreach (CBORObject cborKey2 in items.Keys)
            {
                CBORObject cborValue = items[cborKey2];
                CBORObject cborKey = cborKey2;
                string strKey = cborKey.AsString();

                if ((strKey.Length > 4) && (strKey.Substring(strKey.Length - 4, 4) == "_hex"))
                {
                    cborKey = CBORObject.FromObject(strKey.Substring(0, strKey.Length - 4));
                    cborValue = CBORObject.FromObject(FromHex(cborValue.AsString()));
                }

                if (cborKey.AsString() == "comment")
                {
                    continue;
                }

                switch (cborKey.AsString())
                {
                    case "alg":
                        break;

                    case "kid":
                    binFromText:
                        break;

                    case "epk":
                        break;

                    case "spk":
                        break;

                    case "salt":
                        goto binFromText;

                    case "apu_id":
                        goto binFromText;

                    case "apv_id":
                        goto binFromText;
                    case "apu_nonce":
                        goto binFromText;
                    case "apv_nonce":
                        goto binFromText;
                    case "apu_other":
                        goto binFromText;
                    case "apv_other":
                        goto binFromText;
                    case "pub_other":
                        goto binFromText;
                    case "priv_other":
                        goto binFromText;
                    case "spk_kid":
                        goto binFromText;

                    case "IV":
                        goto binFromText;
                    case "partialIV":
                        goto binFromText;

                    case "crit":

                        break;

                    case "op time":
                        {
                            DateTime when = DateTime.Parse(cborValue.AsString());
                            cborValue = CBORObject.FromObject(
                                (long)(when - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds);

                        }
                        break;

                    case "ctyp":
                        break;


                    case "x5u":
                        break;

                    case "x5u-sender":
                        break;

                    default:
                        break;
                }

                switch (destination)
                {
                    case 0:
                        msg.AddAttribute(cborKey, cborValue, Attributes.PROTECTED);
                        break;
                    case 1:
                        msg.AddAttribute(cborKey, cborValue, Attributes.UNPROTECTED);
                        break;
                    case 2:
                        msg.AddAttribute(cborKey, cborValue, Attributes.DO_NOT_SEND);
                        break;
                    case 4:
                        map[cborKey] = cborValue;
                        break;
                }
            }
        }

        public static bool HasFailMarker(CBORObject cn)
        {
            CBORObject cnFail = cn["fail"];
            if (cnFail != null && cnFail.AsBoolean()) return true;
            return false;
        }

        public static byte[] FromHex(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        static Com.AugustCellars.JOSE.Recipient GetRecipient(CBORObject control)
        {
            Com.AugustCellars.JOSE.JWK key;

            if (!control.ContainsKey("alg")) throw new Exception("Recipient missing alg field");

            if (control.ContainsKey("key")) {
                key = new Com.AugustCellars.JOSE.JWK(control["key"]);
            }
            else if (control.ContainsKey("pwd")) {
                key = new Com.AugustCellars.JOSE.JWK();
                key.Add("kty", "oct");
                key.Add("k", Com.AugustCellars.JOSE.Message.base64urlencode(Encoding.UTF8.GetBytes(control["pwd"].AsString())));
            }
            else {
                throw new Exception("No key defined for a recipient");
            }

            Com.AugustCellars.JOSE.Recipient recipient = new Com.AugustCellars.JOSE.Recipient(key, control["alg"].AsString());

            //  Double check that alg is the same as in the attributes

            recipient.ClearProtected();
            recipient.ClearUnprotected();

            if (control.ContainsKey("protected")) AddAttributes(recipient, control["protected"], 0);
            if (control.ContainsKey("unprotected")) AddAttributes(recipient, control["unprotected"], 1);

            if (control.ContainsKey("sender_key")) {
                Com.AugustCellars.JOSE.JWK myKey = new Com.AugustCellars.JOSE.JWK(control["sender_key"]);
                recipient.SetSenderKey(myKey);
            }

            return recipient;
        }

        static Recipient SetReceivingAttributes(Recipient recip, CBORObject control)
        {
            JWK key = null;

            if (control.ContainsKey("unsent")) AddAttributes(recip, control["unsent"], 2);

            if (control["key"] != null) key = GetKey(control["key"]);

            recip.SetKey(key);

            return recip;
        }

        static void SetReceivingAttributes(Signer recip, CBORObject control)
        {
            if (control.ContainsKey("unsent")) AddAttributes(recip, control["unsent"], 2);
        }

        static CBORObject GetAttribute(CBORObject obj, string attrName)
        {
            if (obj.ContainsKey("protected") && obj["protected"].ContainsKey(attrName))
                return obj["protected"][attrName];
            if (obj.ContainsKey("unprotected") && obj["unprotected"].ContainsKey(attrName))
                return obj["unprotected"][attrName];
            if (obj.ContainsKey("unsent") && obj["unsent"].ContainsKey(attrName)) return obj["unsent"][attrName];
            return null;
        }

        static JWK GetKey(CBORObject control, bool fPublicKey = false)
        {
            JWK jwk = new JWK(control);

            if (fPublicKey && (control["kty"].AsString() != "oct")) {
                return jwk.PublicKey();
            }

            return jwk;
        }
    }
}
