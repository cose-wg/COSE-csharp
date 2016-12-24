using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using PeterO.Cbor;
using NUnit.Framework;
using Com.AugustCellars.COSE;

namespace Com.AugustCellars.COSE.Tests
{
    public class SignerTest
    {

        public SignerTest()
        {
        }

#if false
        /**
         * Test of setKey method, of class Signer.
         */
        [Ignore("Not done")]
        [Test]
        public void testSetKey()
        {
            OneKey cnKey = null;
            Signer instance = new Signer();
        instance.setKey(cnKey);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
#endif

        [Test]
        public void signerDecodeWrongBasis()
        {
            CBORObject obj = CBORObject.NewMap();


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }

        [Test]
        public void signerDecodeWrongCount()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }

        [Test]
        public void signerDecodeBadProtected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }

        [Test]
        public void signerDecodeBadProtected2()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.False));
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }

        [Test]
        public void signerDecodeBadUnprotected()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.False);
            obj.Add(CBORObject.False);


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }

        [Test]
        public void signerDecodeBadSignature()
        {
            CBORObject obj = CBORObject.NewArray();
            obj.Add(CBORObject.FromObject(CBORObject.NewArray()).EncodeToBytes());
            obj.Add(CBORObject.NewMap());
            obj.Add(CBORObject.False);


            Signer sig = new Signer();
            CoseException e = Assert.Throws<CoseException>(() =>
                sig.DecodeFromCBORObject(obj));
            Assert.That(e.Message, Is.EqualTo("Invalid Signer structure"));
        }
    }
}
