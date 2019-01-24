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
        byte[] rgbContent = Encoding.UTF8.GetBytes("This is some content");
        byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        /**
         * Test of decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void TestRoundTrip()
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

        /**
         * Test of decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void TestRoundTrip2()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = Encrypt0Message.DecodeFromBytes(rgbMsg);
            byte[] contentNew = msg.Decrypt(rgbKey128);

            CollectionAssert.AreEqual(rgbContent, (contentNew));
        }

        /**
         * Test of decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void TestRoundTrip3()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject rgbMsg = msg.EncodeToCBORObject();

            msg = Encrypt0Message.DecodeFromCBOR(rgbMsg);
            byte[] contentNew = msg.Decrypt(rgbKey128);

            CollectionAssert.AreEqual(rgbContent, (contentNew));
        }

        /**
  * Test of decrypt method, of class Encrypt0Message.
  */
        [TestMethod]
        public void TestRoundTrip4()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject rgbMsg = msg.EncodeToCBORObject();

            msg = (Encrypt0Message) Message.DecodeFromCBOR(rgbMsg);
            byte[] contentNew = msg.Decrypt(rgbKey128);

            CollectionAssert.AreEqual(rgbContent, (contentNew));
        }

        [TestMethod]
        public void EncryptNoAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.SetContent(rgbContent);

            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("No Algorithm Specified"));
        }

        [TestMethod]
        public void EncryptUnknownAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void EncryptUnsupportedAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void EncryptIncorrectKeySize()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey256));
            Assert.AreEqual(e.Message, ("Incorrect Key Size"));
        }

        [TestMethod]
        public void EncryptNullKey()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            Assert.ThrowsException<CoseException>(() =>
                                                      msg.Encrypt(null));
        }

        [TestMethod]
        public void EncryptNoContent()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.AreEqual(e.Message, ("No Content Specified"));
        }

        [TestMethod]
        public void EncryptBadIV()
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
        public void EncryptIncorrectIV()
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
        public void EncryptNoTag()
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
        public void EncryptNoEmitContent()
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
        public void NoContentForDecrypt()
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
        public void RoundTripDetached()
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
        public void EncryptWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void EncryptDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.AreEqual(e.Message, ("Invalid Encrypt0 structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadProtected()
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
        public void EncryptDecodeBadProtected2()
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
        public void EncryptDecodeBadUnprotected()
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
        public void EncryptDecodeBadContent()
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
        public void EncryptDecodeBadTag()
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
