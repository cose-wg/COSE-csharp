using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;
using Com.AugustCellars.COSE;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Com.AugustCellars.COSE.Tests
{
    [TestClass]
    public class Sign0MessageTest
    {
        static byte[] rgbContent = UTF8Encoding.UTF8.GetBytes("This is some content");

        static OneKey cnKeyPublic;
        static OneKey cnKeyPrivate;


        [TestInitialize]
        public void setUpClass()
        {
            cnKeyPrivate = OneKey.GenerateKey(null, GeneralValues.KeyType_EC, "P-256");
            cnKeyPublic = cnKeyPrivate.PublicKey();
        }

        /**
         * Test of Decrypt method, of class Encrypt0Message.
         */
        [TestMethod]
        public void testRoundTrip()
        {
            Sign1Message msg = new Sign1Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            msg.Sign(cnKeyPrivate);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (Sign1Message)Message.DecodeFromBytes(rgbMsg, Tags.Sign1);
            Boolean f = msg.Validate(cnKeyPublic);
            Assert.AreEqual(f, (true));
        }

        [Ignore("Uses a default algorithm - different from JAVA - review this")]
        [TestMethod]
        public void noAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.AreEqual(e.Message, ("No Algorithm Specified"));
        }

        [TestMethod]
        public void unknownAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void unsupportedAlgorithm()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.AreEqual(e.Message, ("Unknown Algorithm Specified"));
        }

        [TestMethod]
        public void nullKey()
        {
            Sign1Message msg = new Sign1Message();
            OneKey key = null;

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            Assert.ThrowsException<NullReferenceException>(() =>
                msg.Sign(key));
        }

        [TestMethod]
        public void noContent()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Sign(cnKeyPrivate));
            Assert.AreEqual(e.Message, ("No Content Specified"));
        }

        [TestMethod]
        public void publicKey()
        {
            Sign1Message msg = new Sign1Message();

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            msg.SetContent(rgbContent);
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                msg.Sign(cnKeyPublic));
            Assert.AreEqual(e.Message, ("Private key required to sign"));
        }

        [TestMethod]
        public void decodeWrongBasis()

        {
            CBORObject obj = CBORObject.NewMap();


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void codeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }

        [TestMethod]
        public void decodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }

        [TestMethod]
        public void decodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False.EncodeToBytes()));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }

        [TestMethod]
        public void decodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }

        [TestMethod]
        public void decodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }

        [TestMethod]
        public void decodeBadSignature()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign1));
            Assert.AreEqual(e.Message, ("Invalid Sign1 structure"));
        }
    }
}
