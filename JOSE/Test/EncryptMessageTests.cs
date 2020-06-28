using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE.Tests
{
    [TestClass]
    public class EncryptMessageTests
    {
        [TestMethod]
        public void ContentErrors()
        {
            CBORObject test = CBORObject.NewMap();

            //  Empty message - we default to a signed message
            JoseException e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("field 'signatures' must be present.", e.Message);

            //  Cipher field is not base64
            test.Add("ciphertext", " **}");
            FormatException format = Assert.ThrowsException<FormatException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("The input is not a valid Base-64 string as it contains a non-base 64 character, more than two padding characters, or an illegal character among the padding characters.",
                format.Message);

            //  Add the ciphertext field
            test["ciphertext"] = CBORObject.FromObject("ABCD");
            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("One of protected, unprotected or headers must be present for every recipient", e.Message);

            // Add an wrong empty recipients structure
            test.Add("recipients", CBORObject.NewMap());
            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("field 'recipients' must be a non-empty array", e.Message);

            test["recipients"] = CBORObject.NewArray();
            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("field 'recipients' must be a non-empty array", e.Message);

            test["recipients"].Add(CBORObject.NewArray());
            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromJSON(test)
            );
            Assert.AreEqual("recipient must be a map", e.Message);

            test["recipients"][0] = CBORObject.NewMap();
            Message.DecodeFromJSON(test);

        }

        [TestMethod]
        public void EncryptCompressed()
        {
            string msg = "Ths is some content";
            EncryptMessage encryptMessage = new EncryptMessage();
            encryptMessage.SetContent(msg);
            JWK encryptionKey = JWK.GenerateKey("A128GCM");

            // encryptMessage.AddAttribute(HeaderKeys.EncryptionAlgorithm, CBORObject.FromObject(EncryptionAlgorithm), Attributes.PROTECTED);

            Recipient recipient = new Recipient(encryptionKey);
            encryptMessage.AddRecipient(recipient);
            // recipient.ClearUnprotected();
            if (recipient.RecipientType == RecipientType.Direct && encryptionKey.ContainsName("alg")) {
                encryptMessage.AddAttribute("enc", encryptionKey.AsString("alg"), Attributes.PROTECTED);
            }
            else {
                encryptMessage.AddAttribute("enc", "A128GCM", Attributes.PROTECTED);
            }

            msg = encryptMessage.EncodeCompressed();

        }

    }
}
