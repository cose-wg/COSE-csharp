﻿using System;
using System.Text;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace COSETests
{
    /// <summary>
    /// Summary description for EnvelopedMessageTests
    /// </summary>
    [TestClass]
    public class EnvelopedMessageTests
    {
        byte[] rgbKey128 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] rgbKey256 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        String strContent = "This is some content";
        byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
        CBORObject cnKey128;
        Key key128;

        [TestInitialize()]
        public void Setup()
        {
            cnKey128 = CBORObject.NewMap();
            cnKey128.Add(CoseKeyKeys.KeyType, GeneralValues.KeyType_Octet);
            cnKey128.Add(CoseKeyParameterKeys.Octet_k, CBORObject.FromObject(rgbKey128));
            key128 = new Key(cnKey128);
        }

#if false
        [TestMethod()]
        public void EnvelopedMessageTest()
        {
            Assert.Fail();
        }

        [TestMethod()]
        public void DecodeFromCBORObjectTest()
        {
            Assert.Fail();
        }

        [TestMethod()]
        public void EncodeTest()
        {
            Assert.Fail();
        }
#endif

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Message is not a COSE security Message")]
        public void decodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();

            byte[] rgb = obj.EncodeToBytes();
            Message msg = Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt structure")]
        public void decodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt structure")]
        public void decodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False.EncodeToBytes()));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewMap().EncodeToBytes()));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(new byte[0]));
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.Null);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Enveloped);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Algorithm Specified")]
        public void noAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "Unknown Algorithm Specified")]
        public void unknownAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), Attributes.PROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "Unsupported Algorithm Specified")]
        public void unsupportedAlgorithm()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Recipient Specified")]
        public void nullKey()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.SetContent(strContent);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Content Specified")]
        public void noContent()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "IV is incorrectly formed")]
        public void badIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "IV size is incorrectly")]
        public void incorrectIV()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
        }

        [TestMethod()]
        public void encryptNoTag()
        {
            EncryptMessage msg = new EncryptMessage(false, true);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.IsFalse(cn.IsTagged);
        }

        [TestMethod()]
        public void encryptNoEmitContent()
        {
            EncryptMessage msg = new EncryptMessage(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.IsTrue(cn[2].IsNull);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Enveloped Content Supplied")]
        public void noContentForDecrypt()
        {
            EncryptMessage msg = new EncryptMessage(true, false);

            //        thrown.expect(CoseException.class);
            //        thrown.expectMessage("No Enveloped Content Specified");

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();

            byte[] rgb = msg.EncodeToBytes();

            msg = (EncryptMessage) Message.DecodeFromBytes(rgb);
            r = msg.RecipientList[0];
            r.SetKey(key128);
            msg.Decrypt(r);

        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Recipient Supplied")]
        public void nullKeyForDecrypt()
        {
            EncryptMessage msg = new EncryptMessage(true, true);

            //        thrown.expect(CoseException.class);
            //        thrown.expectMessage("No Enveloped Content Specified");

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();

            byte[] rgb = msg.EncodeToBytes();

            msg = (EncryptMessage) Message.DecodeFromBytes(rgb);
            msg.Decrypt(null);

        }

        [TestMethod()]
        public void roundTripDetached()
        {
            EncryptMessage msg = new EncryptMessage(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();

            byte[] content = msg.GetEncryptedContent();

            byte[] rgb = msg.EncodeToBytes();

            msg = (EncryptMessage) Message.DecodeFromBytes(rgb);
            msg.SetEncryptedContent(content);
            r = msg.RecipientList[0];
            r.SetKey(key128);
            msg.Decrypt(r);

        }

        [TestMethod()]
        public void roundTrip()
        {
            EncryptMessage msg = new EncryptMessage();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), Attributes.UNPROTECTED);
            msg.SetContent(strContent);
            Recipient r = new Recipient(key128, AlgorithmValues.Direct);
            msg.AddRecipient(r);
            msg.Encrypt();
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (EncryptMessage) Message.DecodeFromBytes(rgbMsg);
            r = msg.RecipientList[0];
            r.SetKey(key128);
            msg.Decrypt(r);

            Assert.AreEqual<string>(msg.GetContentAsString(), strContent);
        }
    }
}
