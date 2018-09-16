using System;
using System.Text;
using PeterO.Cbor;
using Microsoft.VisualStudio.TestTools.UnitTesting;


namespace Com.AugustCellars.COSE.Tests
{
    [TestClass]
    public class Encrypt0MessageTest
    {
        byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");
        byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        public Encrypt0MessageTest()
        {
        }

        /**
         * Test of decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void testRoundTrip()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (Encrypt0Message)Message.DecodeFromBytes(rgbMsg, Tags.Encrypt0);
            byte[] contentNew = msg.Decrypt(rgbKey128);

            CollectionAssert.AreEqual(rgbContent, (contentNew));
        }

        [TestMethod]
        public void encryptNoAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.SetContent(rgbContent);

            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("No Algorithm Specified"));
        }

        [TestMethod]
        public void encryptUnknownAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void encryptUnsupportedAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void encryptIncorrectKeySize()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey256));
            Assert.AreEqual(e.Message, ("Incorrect Key Size"));
        }

        [TestMethod]
        public void encryptNullKey()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(null));
        }

        [TestMethod]
        public void encryptNoContent()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("No Content Specified"));
        }

        [TestMethod]
        public void encryptBadIV()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("IV is incorrectly formed."));
        }

        [TestMethod]
        public void encryptIncorrectIV()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("IV size is incorrect."));
        }

        [TestMethod]
        public void encryptNoTag()
        {
            Encrypt0Message msg = new Encrypt0Message(false, true);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();

            Assert.AreEqual(cn.IsTagged, (false));
        }

        [TestMethod]
        public void encryptNoEmitContent()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.AreEqual(cn[2].IsNull, (true));
        }

        [TestMethod]
        public void noContentForDecrypt()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);


            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message)Message.DecodeFromBytes(rgb);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Decrypt(rgbKey128));

            Assert.AreEqual(e.Message, ("No Encrypted Content Specified."));
        }

        [TestMethod]
        public void roundTripDetached()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);

            byte[] content = msg.GetEncryptedContent();

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message)Message.DecodeFromBytes(rgb);
            msg.SetEncryptedContent(content);
            msg.Decrypt(rgbKey128);

        }

        [TestMethod]
        public void encryptWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void encryptDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void encryptDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void encryptDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void encryptDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void encryptDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void encryptDecodeBadTag()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));

        }
    }
}
