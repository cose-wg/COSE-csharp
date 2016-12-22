using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;
using Com.AugustCellars.COSE;
using NUnit.Framework;

namespace Com.AugustCellars.COSE.Tests
{
    public class Sign0MessageTest
    {
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");

        static OneKey cnKeyPublic;
        static OneKey cnKeyPrivate;


        [OneTimeSetUp]
        public static void setUpClass()
        {
            cnKeyPrivate = OneKey.GenerateKey(null, GeneralValues.KeyType_EC, "P-256");
            cnKeyPublic = cnKeyPrivate.PublicKey();
        }

        /**
         * Test of Decrypt method, of class Encrypt0Message.
         */
        [Test]
        public void testRoundTrip()
        {
            Sign1Message msg = new Sign1Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Sign(cnKeyPrivate);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (Sign1Message)Message.DecodeFromBytes(rgbMsg, Tags.Sign1);
            Boolean f = msg.Validate(cnKeyPublic);
            Assert.That(f, Is.EqualTo(true));
        }

        [Ignore("Uses a default algorithm - different from JAVA - review this")]
        [Test]
        public void noAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.That(e.Message, Is.EqualTo("No Algorithm Specified"));
        }

        [Test]
        public void unknownAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void unsupportedAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.That(e.Message, Is.EqualTo("Unknown Algorithm Specified"));
        }

        [Test]
        public void nullKey()
        {
            Sign1Message msg = new Sign1Message();
            OneKey key = null;

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            Assert.Throws<NullReferenceException>(() =>
                msg.Sign(key));
        }

        [Test]
        public void noContent()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.That(e.Message, Is.EqualTo("No Content Specified"));
        }

        [Test]
        public void publicKey()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.Throws<CoseException>(() =>
                msg.Sign(cnKeyPublic));
            Assert.That(e.Message, Is.EqualTo("Private key required to sign"));
        }

        [Test]
        public void decodeWrongBasis()

        {
            CBORObject obj = CBORObject.NewMap();


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void codeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }

        [Test]
        public void decodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }

        [Test]
        public void decodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False.EncodeToBytes()));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }

        [Test]
        public void decodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }

        [Test]
        public void decodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }

        [Test]
        public void decodeBadSignature()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.That(e.Message, Is.EqualTo("Invalid Sign1 structure"));
        }
    }
}
