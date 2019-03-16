using System.Collections.Generic;
using System.Linq;
using System.Text;
using PeterO.Cbor;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Com.AugustCellars.COSE.Tests
{
    [TestClass]
    public class EncryptMessageTest
    {
        static byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        // static byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static byte[] rgbContent = Encoding.UTF8.GetBytes("This is some content");
        static byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        static byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        Recipient recipient128;
        OneKey cnKey128;


        [TestInitialize]
        
        public void setUp()
        {
            recipient128 = new Recipient();
            recipient128.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.Direct, Attributes.UNPROTECTED);
            CBORObject key128 = CBORObject.NewMap();
            key128.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key128.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(rgbKey128));
            cnKey128 = new OneKey(key128);
            recipient128.SetKey(cnKey128);
        }

        /**
         * Test of Decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void TestRoundTrip()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient128);
            msg.Encrypt();

            List<Recipient> rList = msg.RecipientList;
            Assert.AreEqual(rList.Count(), (1));

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (EncryptMessage)Message.DecodeFromBytes(rgbMsg, Tags.Encrypt);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey128);
            byte[] contentNew = msg.Decrypt(r);

            CollectionAssert.AreEqual(contentNew, (rgbContent));
        }

        [TestMethod]
        public void TestRoundTrip2()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient128);
            msg.Encrypt();

            List<Recipient> rList = msg.RecipientList;
            Assert.AreEqual(rList.Count(), (1));

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = EncryptMessage.DecodeFromBytes(rgbMsg);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey128);
            byte[] contentNew = msg.Decrypt(r);

            CollectionAssert.AreEqual(contentNew, (rgbContent));
        }
        [TestMethod]
        public void TestRoundTrip3()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient128);
            msg.Encrypt();

            List<Recipient> rList = msg.RecipientList;
            Assert.AreEqual(rList.Count(), (1));

            CBORObject rgbMsg = msg.EncodeToCBORObject();

            msg = (EncryptMessage)Message.DecodeFromCBOR(rgbMsg, Tags.Encrypt);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey128);
            byte[] contentNew = msg.Decrypt(r);

            CollectionAssert.AreEqual(contentNew, (rgbContent));
        }
        [TestMethod]
        public void TestRoundTrip4()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient128);
            msg.Encrypt();

            List<Recipient> rList = msg.RecipientList;
            Assert.AreEqual(rList.Count(), (1));

            CBORObject rgbMsg = msg.EncodeToCBORObject();

            msg = EncryptMessage.DecodeFromCBOR(rgbMsg);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey128);
            byte[] contentNew = msg.Decrypt(r);

            CollectionAssert.AreEqual(contentNew, (rgbContent));
        }

        [TestMethod]
        public void TestRecipientListCount()
        {
            EncryptMessage msg = new EncryptMessage();

            Assert.AreEqual(msg.RecipientList.Count, (0));

            Recipient r = new Recipient();
            msg.AddRecipient(r);
            Assert.AreEqual(msg.RecipientList.Count, (1));
        }

        [TestMethod]
        public void EncryptNoRecipients()
        {
            EncryptMessage msg = new EncryptMessage();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());

            Assert.AreEqual(e.Message, ("No recipients supplied"));
        }

        [TestMethod]
        public void EncryptNoAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("No Algorithm Specified"));
        }

        [TestMethod]
        public void EncryptUnknownAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void EncryptUnsupportedAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("Incorrect key size" /*"Unsupported Algorithm Specified"*/));
        }

        [TestMethod]
        public void EncryptNoContent()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("No Content Specified"));
        }

        [TestMethod]
        public void EncryptBadIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("IV is incorrectly formed."));
        }

        [TestMethod]
        public void EncryptIncorrectIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Encrypt());
            Assert.AreEqual(e.Message, ("IV size is incorrect."));
        }

        [TestMethod]
        public void EncryptDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void EncryptDecodeWrongCount()

        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadProtected()

        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }

        [TestMethod]
        public void EncryptDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.AreEqual(e.Message, ("Invalid Encrypt structure"));
        }
    }
}
