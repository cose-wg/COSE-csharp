using System;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;

namespace Com.AugustCellars.COSE.Tests
{
    public class MessageTest
    {
        byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] rgbContent = new byte[] { 1, 2, 3, 4, 5, 6, 7 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        public MessageTest()
        {
        }

        /**
         * Test of DecodeFromBytes method, of class Message.
         */
        [TestMethod]
        public void testDecodeUnknown()
        {
            Encrypt0Message msg = new Encrypt0Message(false, true);
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg = (Encrypt0Message)Message.DecodeFromBytes(rgbMsg, Tags.Unknown));
            Assert.AreEqual(e.Message, ("Message was not tagged and no default tagging option given"));
        }

        /**
         * Test of DecodeFromBytes method, of class Message.
         */
        [TestMethod]
        public void testDecodeFromBytes_byteArr_MessageTag()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (Encrypt0Message)Message.DecodeFromBytes(rgbMsg);
            Assert.AreEqual(false, (msg.HasContent()));
        }

        /**
         * Test of HasContent method, of class Message.
         */
        [TestMethod]
        public void testHasContent()
        {
            Message instance = new Encrypt0Message();
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
            Message instance = new Encrypt0Message();
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

            Message instance = new Encrypt0Message();
            instance.SetContent(strData);
            byte[] result = instance.GetContent();
            Assert.AreEqual(result, (rgbData));
        }
    }
}
