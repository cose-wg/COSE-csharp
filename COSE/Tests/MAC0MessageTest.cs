using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE.Tests
{
    [TestClass]
    public class MAC0MessageTest
    {
        static byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        static byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");

        OneKey cnKey256;

        public MAC0MessageTest()
        {
        }

        [TestInitialize]
        public void setUp()
        {

            CBORObject cnKey = CBORObject.NewMap();
            cnKey.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            cnKey.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(rgbKey256));
            cnKey256 = new OneKey(cnKey);
        }

        /**
         * Test of Decrypt method, of class Encrypt0Message.
         */

        [TestMethod]
        public void testRoundTrip()
        {
            MAC0Message msg = new MAC0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Compute(rgbKey256);

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (MAC0Message)Message.DecodeFromBytes(rgbMsg, Tags.MAC0);
            Boolean contentNew = msg.Validate(rgbKey256);
            Assert.AreEqual(contentNew, (true));
        }

        [Ignore("Uses default algorithm - Ealuate this")]
        [TestMethod]
        public void macNoAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.AreEqual(e.Message, ("No Algorithm Specified"));
        }

        [TestMethod]
        public void macUnknownAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void macUnsupportedAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CCM_16_64_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.AreEqual(e.Message, ("MAC algorithm not recognized 11"));
        }

        [TestMethod]
        public void macNoContent()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.AreEqual(e.Message, ("No Content Specified"));
        }

        [TestMethod]
        public void macDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void macDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }

        [TestMethod]
        public void macDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }

        [TestMethod]
        public void macDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }

        [TestMethod]
        public void macDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }

        [TestMethod]
        public void macDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }

        [TestMethod]
        public void macDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.AreEqual(e.Message, ("Invalid MAC0 structure"));
        }
    }
}
