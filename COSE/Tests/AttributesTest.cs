// <copyright file="AttributesTest.cs" company="August Cellars">Copyright © August Cellars 2016</copyright>
using System;
using Com.AugustCellars.COSE;
// using NUnit.Framework;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;

namespace Com.AugustCellars.COSE.Tests
{
    [TestClass()]
    public class AttributesTest
    {
        [TestMethod()]
        public void testAddAttribute_1()
        {
            CBORObject label = CBORObject.FromObject(new byte[1]);
            CBORObject value = null;
            int where = Attributes.PROTECTED;
            Attributes instance = new Attributes();

            try {
                instance.AddAttribute(label, value, where);
            }
            catch (CoseException e) {
                Assert.AreEqual(e.Message, "Labels must be integers or strings");
            }
        }

        [TestMethod]
        public void testAddAttribute_2()
        {
            CBORObject label = CBORObject.FromObject(1);
            CBORObject value = CBORObject.FromObject(2);
            int where = 0;
            Attributes instance = new Attributes();

            try {
                instance.AddAttribute(label, value, where);
            }
            catch (CoseException e) {
                Assert.AreEqual(e.Message, "Invalid attribute location given");
            }
        }

        [TestMethod]
        public void testAddAttribute_3()
        {
            byte[] rgbKey = new byte[256 / 8];
            MAC0Message msg = new MAC0Message();
            msg.SetContent("ABCDE");
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.Compute(rgbKey);

            try {
                msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            }
            catch (CoseException e) {
                Assert.AreEqual(e.Message, "Operation would modify integrity protected attributes");
            }
        }

        [TestMethod]
        public void testAddAttribute_4()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CBC_MAC_128_128, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.AES_CBC_MAC_128_64, Attributes.UNPROTECTED);
            instance.AddAttribute(HeaderKeys.CounterSignature, AlgorithmValues.AES_CBC_MAC_256_64, Attributes.DO_NOT_SEND);

            CBORObject cn;

            cn = instance.FindAttribute(HeaderKeys.Algorithm, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.AES_CBC_MAC_128_128);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.ContentType, Attributes.UNPROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.AES_CBC_MAC_128_64);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.PROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.CounterSignature, Attributes.DO_NOT_SEND);
            Assert.AreEqual(cn, AlgorithmValues.AES_CBC_MAC_256_64);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.CounterSignature, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.CounterSignature, Attributes.PROTECTED));
        }

        [TestMethod]
        public void testAddAttribute_5()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CBC_MAC_128_128, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.AES_CBC_MAC_128_64, Attributes.UNPROTECTED);

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.ECDH_ES_HKDF_256, Attributes.PROTECTED);

            CBORObject cn;

            cn = instance.FindAttribute(HeaderKeys.Algorithm, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.ECDSA_256);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.ContentType, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.ECDH_ES_HKDF_256);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.DO_NOT_SEND));
        }

        [TestMethod]
        public void removeAttribute()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_CBC_MAC_128_128, Attributes.PROTECTED);

            CBORObject cn;
            cn = instance.FindAttribute(HeaderKeys.Algorithm);
            Assert.AreEqual(cn, AlgorithmValues.AES_CBC_MAC_128_128);

            instance.RemoveAttribute(HeaderKeys.Algorithm);
            cn = instance.FindAttribute(HeaderKeys.Algorithm);
            Assert.AreEqual(cn, null);
        }

    }
}
