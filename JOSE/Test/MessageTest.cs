using System;
using System.Text;
using Com.AugustCellars.JOSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE.Tests
{
    [TestClass]
    public class MessageTest
    {
        byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] rgbContent = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };


#if false
        /**
         * Test of DecodeFromBytes method, of class Message.
         */
        [TestMethod]
        public void TestDecodeUnknown()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            // msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);

            CBORObject obj = CBORObject.NewMap();
            obj.Add("kty", "oct");
            obj.Add("k", Encoding.UTF8.GetString(Base64.Encode(rgbKey128)));

            JWK key = new JWK(obj);

            Recipient recipient = new Recipient(key, "dir");
            msg.AddRecipient(recipient);
            string rgbMsg = msg.Encode();

            JoseException e = Assert.ThrowsException<JoseException>(() =>
                msg = (EncryptMessage)Message.DecodeFromString(rgbMsg));
            Assert.AreEqual(e.Message, ("Message was not tagged and no default tagging option given"));
        }

        /**
         * Test of DecodeFromBytes method, of class Message.
         */
        [TestMethod]
        public void testDecodeFromBytes_byteArr_MessageTag()
        {
            EncryptMessage msg = new EncryptMessage(true, false);
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (EncryptMessage)Message.DecodeFromBytes(rgbMsg);
            Assert.AreEqual(false, (msg.HasContent()));
        }

        /**
         * Test of HasContent method, of class Message.
         */
        [TestMethod]
        public void testHasContent()
        {
            Message instance = new EncryptMessage();
            Boolean expResult = false;
            Boolean result = instance.HasContent();
            Assert.AreEqual(expResult, (expResult));

            instance.SetContent(new byte[10]);
            result = instance.HasContent();
            Assert.AreEqual(result, (true));
        }

        /**
         * Test of SetContent method, of class Message.
         */
        [TestMethod]
        public void testSetContent_byteArr()
        {
            byte[] rgbData = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
            Message instance = new EncryptMessage();
            instance.SetContent(rgbData);

            byte[] result = instance.GetContent();
            Assert.AreEqual(result, (rgbData));
        }

        /**
         * Test of SetContent method, of class Message.
         */
        [TestMethod]
        public void testSetContent_String()
        {
            String strData = "12345678";
            byte[] rgbData = new byte[] { 49, 50, 51, 52, 53, 54, 55, 56 };

            Message instance = new EncryptMessage();
            instance.SetContent(strData);
            byte[] result = instance.GetContent();
            Assert.AreEqual(result, (rgbData));
        }
#endif

        [TestMethod]
        public void TestBadJson()
        {
            CBORException e = Assert.ThrowsException<CBORException>(() =>
                Message.DecodeFromString("{\"qr\":\"field\""));
            Assert.AreEqual(e.Message, ("Expected a ',' or '}' (offset 13)"));

        }

        [TestMethod]
        public void TestBadDotCount()
        {
            JoseException e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromString("This string has no dots in it"));
            Assert.AreEqual(e.Message, "There are not the correct number of dots.");

            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromString("This string has one. dots in it"));
            Assert.AreEqual(e.Message, "There are not the correct number of dots.");

            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromString("This. string has three. dots in. it"));
            Assert.AreEqual(e.Message, "There are not the correct number of dots.");

            e = Assert.ThrowsException<JoseException>(() =>
                Message.DecodeFromString("This. string. has. six. dots. in. it"));
            Assert.AreEqual(e.Message, "There are not the correct number of dots.");

        }
    }
}
