using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE.Test
{
    public class MAC0MessageTest
    {
        static byte[] rgbKey128 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        static byte[] rgbKey256 = { (byte)'a', (byte)'b', (byte)'c', 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");

        OneKey cnKey256;

        public MAC0MessageTest()
        {
        }

        [OneTimeSetUp]
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

        [Test]
        public void testRoundTrip()
        {
            MAC0Message msg = new MAC0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Compute(rgbKey256);

            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (MAC0Message)Message.DecodeFromBytes(rgbMsg, Tags.MAC0);
            Boolean contentNew = msg.Validate(rgbKey256);
            Assert.That(contentNew, Is.EqualTo(true));
        }

        [Ignore("Uses default algorithm - Ealuate this")]
        [Test]
        public void macNoAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.That(e.Message, Is.EqualTo("No Algorithm Specified"));
        }

        [Test]
        public void macUnknownAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void macUnsupportedAlgorithm()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CCM_16_64_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.That(e.Message, Is.EqualTo("MAC algorithm not recognized 11"));
        }

        [Test]
        public void macNoContent()
        {
            MAC0Message msg = new MAC0Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Compute(rgbKey256));
            Assert.That(e.Message, Is.EqualTo("No Content Specified"));
        }

        [Test]
        public void macDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();
            Message msg;


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
            msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void macDecodeWrongCount()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }

        [Test]
        public void macDecodeBadProtected()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }

        [Test]
        public void macDecodeBadProtected2()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }

        [Test]
        public void macDecodeBadUnprotected()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }

        [Test]
        public void macDecodeBadContent()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }

        [Test]
        public void macDecodeBadRecipients()
        {
            Message msg;
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                msg = Message.DecodeFromBytes(rgb, Tags.MAC0));
            Assert.That(e.Message, Is.EqualTo("Invalid MAC0 structure"));
        }
    }
}
