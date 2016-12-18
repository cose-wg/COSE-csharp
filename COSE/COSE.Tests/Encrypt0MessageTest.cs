using System;
using System.Text;
using PeterO.Cbor;
using NUnit.Framework;

namespace Com.AugustCellars.COSE.Tests
{
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
        [Test]
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

            Assert.That(rgbContent, Is.EqualTo(contentNew));
        }

        [Test]
        public void encryptNoAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.SetContent(rgbContent);

            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("No Algorithm Specified"));
        }

        [Test]
        public void encryptUnknownAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void encryptUnsupportedAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void encryptIncorrectKeySize()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey256));
            Assert.That(e.Message, Is.EqualTo("Incorrect Key Size"));
        }

        [Test]
        public void encryptNullKey()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(null));
        }

        [Test]
        public void encryptNoContent()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("No Content Specified"));
        }

        [Test]
        public void encryptBadIV()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("IV is incorrectly formed."));
        }

        [Test]
        public void encryptIncorrectIV()
        {
            Encrypt0Message msg = new Encrypt0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Encrypt(rgbKey128));
            Assert.That(e.Message, Is.EqualTo("IV size is incorrect."));
        }

        [Test]
        public void encryptNoTag()
        {
            Encrypt0Message msg = new Encrypt0Message(false, true);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();

            Assert.That(cn.IsTagged, Is.EqualTo(false));
        }

        [Test]
        public void encryptNoEmitContent()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.That(cn[2].IsNull, Is.EqualTo(true));
        }

        [Test]
        public void noContentForDecrypt()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);


            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(rgbContent);
            msg.Encrypt(rgbKey128);

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message)Message.DecodeFromBytes(rgb);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Decrypt(rgbKey128));

            Assert.That(e.Message, Is.EqualTo("No Encrypted Content Specified."));
        }

        [Test]
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

        [Test]
        public void encryptWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();
            Message msg;

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void encryptDecodeWrongCount()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));
        }

        [Test]
        public void encryptDecodeBadProtected()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));
        }

        [Test]
        public void encryptDecodeBadProtected2()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));
        }

        [Test]
        public void encryptDecodeBadUnprotected()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));
        }

        [Test]
        public void encryptDecodeBadContent()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));
        }

        [Test]
        public void encryptDecodeBadTag()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.Encrypt0));
            Assert.That(e.Message, Is.EqualTo("Invalid Encrypt0 structure"));

        }
    }
}
