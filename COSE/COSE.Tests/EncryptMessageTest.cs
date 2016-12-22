using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using PeterO.Cbor;
using NUnit.Framework;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE
{
    public class EncryptMessageTest
    {
        static byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        static byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");
        static byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        static byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

        Recipient recipient128;
        OneKey cnKey128;


        [OneTimeSetUp]
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
        [Test]
        public void testRoundTrip()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient128);
            msg.Encrypt();

            List<Recipient> rList = msg.RecipientList;
            Assert.That(rList.Count(), Is.EqualTo(1));

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (EncryptMessage)Message.DecodeFromBytes(rgbMsg, Tags.Encrypt);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey128);
            byte[] contentNew = msg.Decrypt(r);

            Assert.That(contentNew, Is.EqualTo(rgbContent));
        }

        [Test]
        public void testRecipientListCount()
        {
            EncryptMessage msg = new EncryptMessage();

            Assert.That(msg.RecipientList.Count, Is.EqualTo(0));

            Recipient r = new Recipient();
            msg.AddRecipient(r);
            Assert.That(msg.RecipientList.Count, Is.EqualTo(1));
        }

        [Test]
        public void encryptNoRecipients()
        {
            EncryptMessage msg = new EncryptMessage();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());

            Assert.That(e.Message, Is.EqualTo("No recipients supplied"));
        }

        [Test]
        public void encryptNoAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("No Algorithm Specified"));
        }

        [Test]
        public void encryptUnknownAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void encryptUnsupportedAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("Incorrect key size" /*"Unsupported Algorithm Specified"*/));
        }

        [Test]
        public void encryptNoContent()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("No Content Specified"));
        }

        [Test]
        public void encryptBadIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("IV is incorrectly formed."));
        }

        [Test]
        public void encryptIncorrectIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddRecipient(recipient128);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt());
            Assert.That(e.Message, Is.EqualTo("IV size is incorrect."));
        }

        [Test]
        public void encryptDecodeWrongBasis()

        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void encryptDecodeWrongCount()

        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }

        [Test]
        public void encryptDecodeBadProtected()

        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }

        [Test]
        public void encryptDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }

        [Test]
        public void encryptDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }

        [Test]
        public void encryptDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }

        [Test]
        public void encryptDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Encrypt));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt structure"));
        }
    }
}
