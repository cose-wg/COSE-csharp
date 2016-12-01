using Microsoft.VisualStudio.TestTools.UnitTesting;
using COSE;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PeterO.Cbor;

namespace COSE.Tests
{
    [TestClass()]
    public class EncryptMessageTests
    {
        byte[] rgbKey128 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
        byte[] rgbKey256 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32 };
        String strContent = "This is some content";
        byte[] rgbIV128 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
        byte[] rgbIV96 = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };

#if false
        [TestMethod()]
        public void EncryptMessageTest()
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
            Message msg = Message.DecodeFromBytes(rgb, Tags.Encrypted);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Encrypted);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException),
            "Invalid Encrypt0 structure")]
        public void decodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Encrypted);
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

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Encrypted);
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

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Encrypted);
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

            byte[] rgb = obj.EncodeToBytes();
            Message.DecodeFromBytes(rgb, Tags.Encrypted);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Algorithm Specified")]
        public void noAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "Unknown Algorithm Specified")]
        public void unknownAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, CBORObject.FromObject("Unknown"), true);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "Unsupported Algorithm Specified")]
        public void unsupportedAlgorithm()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, true);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "Incorrect Key Size")]
        public void incorrectKeySize()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey256);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Key Specified")]
        public void nullKey()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.SetContent(strContent);
            msg.Encrypt(null);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Content Specified")]
        public void noContent()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "IV is incorrectly formed")]
        public void badIV()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject("IV"), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "IV size is incorrectly")]
        public void incorrectIV()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV128), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
        }

        [TestMethod()]
        public void encryptNoTag() {
            Encrypt0Message msg = new Encrypt0Message(false, true);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.IsFalse(cn.IsTagged);
        }

        [TestMethod()]
        public void encryptNoEmitContent()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
            CBORObject cn = msg.EncodeToCBORObject();


            Assert.IsTrue(cn[2].IsNull);
        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Encrypted Content Supplied")]
        public void noContentForDecrypt()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            //        thrown.expect(CoseException.class);
            //        thrown.expectMessage("No Encrypted Content Specified");

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
            msg.Decrypt(rgbKey128);

        }

        [TestMethod()]
        [ExpectedException(typeof(CoseException), "No Key Supplied")]
        public void nullKeyForDecrypt()
        {
            Encrypt0Message msg = new Encrypt0Message(true, true);

            //        thrown.expect(CoseException.class);
            //        thrown.expectMessage("No Encrypted Content Specified");

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
            msg.Decrypt(null);

        }

        [TestMethod()]
        public void roundTripDetached()
        {
            Encrypt0Message msg = new Encrypt0Message(true, false);

            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);

            byte[] content = msg.GetEncryptedContent();

            byte[] rgb = msg.EncodeToBytes();

            msg = (Encrypt0Message) Message.DecodeFromBytes(rgb);
            msg.SetEncryptedContent(content);
            msg.Decrypt(rgbKey128);

        }    

        [TestMethod()]
        public void roundTrip()
        {
            Encrypt0Message msg = new Encrypt0Message();
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, true);
            msg.AddAttribute(HeaderKeys.IV, CBORObject.FromObject(rgbIV96), false);
            msg.SetContent(strContent);
            msg.Encrypt(rgbKey128);
            byte[] rgbMsg = msg.EncodeToBytes();

            msg = (Encrypt0Message) Message.DecodeFromBytes(rgbMsg);
            msg.Decrypt(rgbKey128);

            Assert.AreEqual<string>(msg.GetContentAsString(), strContent);
        }
    }
}
