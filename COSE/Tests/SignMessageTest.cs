using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE.Tests
{
    [TestClass]
    public class SignMessageTest
    {

#if false
        /**
         * Test of EncodeCBORObject method, of class SignMessage.
         */
        [Ignore("Unwritten")]
        [TestMethod]
        public void testEncodeCBORObject()
        {
            SignMessage instance = new SignMessage();
        CBORObject expResult = null;
        CBORObject result = instance.EncodeToCBORObject();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }

    /**
     * Test of getSigner method, of class SignMessage.
     */
    [Ignore("Unwritten")]
    [TestMethod]
    public void testGetSigner()
    {
        int iSigner = 0;
        SignMessage instance = new SignMessage();
        Signer expResult = null;
        Signer result = instance.getSigner(iSigner);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
#endif

        [TestMethod]
        public void testGetSignerCount()
        {
            SignMessage msg = new SignMessage();

            Assert.AreEqual(msg.SignerList.Count, (0));

            Signer r = new Signer();
            msg.AddSigner(r);
            Assert.AreEqual(msg.SignerList.Count, (1));
        }

#if false
        /**
         * Test of sign method, of class SignMessage.
         */
        [Ignore("Unwritten")]
    [TestMethod]
    public void testSign()
    {
        SignMessage instance = new SignMessage();
    instance.Encode();
        // TODO review the generated test code and remove the default call to fail.
        /// fail("The test case is a prototype.");
}

/**
 * Test of validate method, of class SignMessage.
 */
[Ignore("Unwritten")]
[TestMethod]
    public void testValidate()
{
    Signer signerToUse = null;
    SignMessage instance = new SignMessage();
Boolean expResult = false;
Boolean result = instance.Validate(signerToUse);
        Assert.AreEqual(expResult, (result));
        // TODO review the generated test code and remove the default call to fail.
        // fail("The test case is a prototype.");
    }
#endif

        [TestMethod]
        public void signDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Message is not a COSE security message."));
        }

        [TestMethod]
        public void signDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }

        [TestMethod]
        public void signDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }

        [TestMethod]
        public void signDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }

        [TestMethod]
        public void signDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }

        [TestMethod]
        public void signDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }

        [TestMethod]
        public void signDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.ThrowsException<CoseException>(() =>

                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.AreEqual(e.Message, ("Invalid SignMessage structure"));
        }
    }
}
