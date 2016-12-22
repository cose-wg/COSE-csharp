using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Com.AugustCellars.COSE;
using PeterO.Cbor;
using NUnit.Framework;

namespace COSE.Tests
{
    public class MACMessageTest
    {
        static byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        static byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");

        Recipient recipient256;
        OneKey cnKey256;

        public MACMessageTest()
        {
        }


        [OneTimeSetUp]
        public void setUp()
        {
            recipient256 = new Recipient();
            recipient256.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.Direct, Attributes.UNPROTECTED);
            CBORObject key256 = CBORObject.NewMap();
            key256.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            key256.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(rgbKey256));
            cnKey256 = new OneKey(key256);
            recipient256.SetKey(cnKey256);
        }

        /**
         * Test of AddRecipient method, of class MACMessage.
         */
        [Test]
        public void testAddRecipient()
        {
            Recipient recipient = null;
            MACMessage instance = new MACMessage();
            CoseException e = Assert.Throws<CoseException>(() =>
                instance.AddRecipient(recipient));
            Assert.That(e.Message, Is.EqualTo("Recipient is null"));           
        }

        /**
         * Test of getRecipient method, of class MACMessage.
         */
        [Test]
        public void testGetRecipient_1args_1()
        {
            int iRecipient = 0;
            MACMessage instance = new MACMessage();
            Recipient expResult = new Recipient();
            instance.AddRecipient(expResult);
            Recipient result = instance.RecipientList[iRecipient];
            Assert.That(Is.ReferenceEquals(expResult, result));
        }

        [Test]
        public void testGetRecipientCount()
        {
            MACMessage msg = new MACMessage();

            Assert.That(msg.RecipientList.Count, Is.EqualTo(0));

            Recipient r = new Recipient();
            msg.AddRecipient(r);
            Assert.That(msg.RecipientList.Count, Is.EqualTo(1));
        }

        /**
         * Test of Decrypt method, of class Encrypt0Message.
         */
        [Test]
        public void testRoundTrip()
        {
            MACMessage msg = new MACMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.AddRecipient(recipient256);
            msg.Compute();

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (MACMessage)Message.DecodeFromBytes(rgbMsg, Tags.MAC);
            Recipient r = msg.RecipientList[0];
            r.SetKey(cnKey256);
            Boolean contentNew = msg.Validate(r);
            Assert.That(contentNew, Is.EqualTo(true));
        }

        [Test]
        public void macNoRecipients()
        {
            MACMessage msg = new MACMessage();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute());
            Assert.That(e.Message, Is.EqualTo("No recipients supplied"));
        }

        [Ignore("Has a default algorith - not same as JAVA should this change?")]
        [Test]
        public void macNoAlgorithm()
        {
            MACMessage msg = new MACMessage();
            msg.AddRecipient(recipient256);

            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute());
            Assert.That(e.Message, Is.EqualTo("No Algorithm Specified"));
        }

        [Test]
        public void macUnknownAlgorithm()
        {
            MACMessage msg = new MACMessage();
            msg.AddRecipient(recipient256);

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute());
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void macUnsupportedAlgorithm()
        {
            MACMessage msg = new MACMessage();
            msg.AddRecipient(recipient256);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CCM_16_64_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute());
            Assert.That(e.Message, Is.EqualTo("MAC algorithm not recognized 11"));
        }

        [Test]
        public void macNoContent()
        {
            MACMessage msg = new MACMessage();
            msg.AddRecipient(recipient256);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute());
            Assert.That(e.Message, Is.EqualTo("No Content Specified"));
        }

        [Test]
        public void macDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void macDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadTag()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.FromObject(rgbContent));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

        [Test]
        public void macDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.FromObject(rgbContent));
            obj.Add(CBORObject.FromObject(rgbContent));
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.MAC));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC structure"));
        }

    }
}
