using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using NUnit.Framework;
using PeterO.Cbor;
using Com.AugustCellars.COSE;

namespace Com.AugustCellers.COSE.Tests
{
    public class SignMessageTest
    {

#if false
        /**
         * Test of EncodeCBORObject method, of class SignMessage.
         */
        [Ignore("Unwritten")]
        [Test]
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
    [Test]
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

        [Test]
        public void testGetSignerCount()
        {
            SignMessage msg = new SignMessage();

            Assert.That(msg.SignerList.Count, Is.EqualTo(0));

            Signer r = new Signer();
            msg.AddSigner(r);
            Assert.That(msg.SignerList.Count, Is.EqualTo(1));
        }

#if false
        /**
         * Test of sign method, of class SignMessage.
         */
        [Ignore("Unwritten")]
    [Test]
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
[Test]
    public void testValidate()
{
    Signer signerToUse = null;
    SignMessage instance = new SignMessage();
Boolean expResult = false;
Boolean result = instance.Validate(signerToUse);
        Assert.That(expResult, Is.EqualTo(result));
        // TODO review the generated test code and remove the default call to fail.
        // fail("The test case is a prototype.");
    }
#endif

        [Test]
        public void signDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Message is not a COSE security message."));
        }

        [Test]
        public void signDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }

        [Test]
        public void signDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }

        [Test]
        public void signDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }

        [Test]
        public void signDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }

        [Test]
        public void signDecodeBadContent()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>
                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }

        [Test]
        public void signDecodeBadRecipients()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(new byte[0]);
            obj.Add(CBORObject.False);


            byte[] rgb = obj.EncodeToBytes();
            CoseException e = Assert.Throws<CoseException>(() =>

                Message.DecodeFromBytes(rgb, Tags.Sign));
            Assert.That(e.Message, Is.EqualTo("Invalid SignMessage structure"));
        }
    }
}
