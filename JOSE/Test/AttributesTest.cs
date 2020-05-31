// <copyright file="AttributesTest.cs" company="August Cellars">Copyright © August Cellars 2016</copyright>
using System;
using Com.AugustCellars.JOSE;
// using NUnit.Framework;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE.Tests
{
    [TestClass()]
    public class AttributesTest
    {
        [TestMethod()]
        public void TestAddAttribute_1()
        {
            CBORObject label = CBORObject.FromObject(new byte[1]);
            CBORObject value = null;
            int where = Attributes.PROTECTED;
            Attributes instance = new Attributes();

            try
            {
                instance.AddAttribute(label, value, where);
            }
            catch (JoseException e)
            {
                Assert.AreEqual(e.Message, "Labels must be integers or strings");
            }
        }

        [TestMethod]
        public void TestAddAttribute_2()
        {
            CBORObject label = CBORObject.FromObject(1);
            CBORObject value = CBORObject.FromObject(2);
            int where = 0;
            Attributes instance = new Attributes();

            try
            {
                instance.AddAttribute(label, value, where);
            }
            catch (JoseException e)
            {
                Assert.AreEqual(e.Message, "Invalid attribute location given");
            }
        }

#if false
        [TestMethod]
        public void TestAddAttribute_3()
        {
            byte[] rgbKey = new byte[256 / 8];
            MAC0Message msg = new MAC0Message();
            msg.SetContent("ABCDE");
            msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.HMAC_SHA_256, Attributes.PROTECTED);
            msg.Compute(rgbKey);

            try
            {
                msg.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            }
            catch (JoseException e)
            {
                Assert.AreEqual(e.Message, "Operation would modify integrity protected attributes");
            }
        }
#endif

        [TestMethod]
        public void TestAddAttribute_4()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.AES_GCM_128, Attributes.UNPROTECTED);
            instance.AddAttribute(HeaderKeys.EncryptionAlgorithm, AlgorithmValues.AES_GCM_128, Attributes.DO_NOT_SEND);

            CBORObject cn;

            cn = instance.FindAttribute(HeaderKeys.Algorithm, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.AES_GCM_128);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.ContentType, Attributes.UNPROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.AES_GCM_128);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.PROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.EncryptionAlgorithm, Attributes.DO_NOT_SEND);
            Assert.AreEqual(cn, AlgorithmValues.AES_GCM_128);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.EncryptionAlgorithm, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.EncryptionAlgorithm, Attributes.PROTECTED));
        }

        [TestMethod]
        public void TestAddAttribute_5()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_128, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.AES_GCM_128, Attributes.UNPROTECTED);

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.ECDSA_256, Attributes.PROTECTED);
            instance.AddAttribute(HeaderKeys.ContentType, AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128, Attributes.PROTECTED);

            CBORObject cn;

            cn = instance.FindAttribute(HeaderKeys.Algorithm, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.ECDSA_256);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.Algorithm, Attributes.DO_NOT_SEND));

            cn = instance.FindAttribute(HeaderKeys.ContentType, Attributes.PROTECTED);
            Assert.AreEqual(cn, AlgorithmValues.ECDH_ES_HKDF_256_AES_KW_128);
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.UNPROTECTED));
            Assert.AreEqual(null, instance.FindAttribute(HeaderKeys.ContentType, Attributes.DO_NOT_SEND));
        }

        [TestMethod]
        public void RemoveAttribute()
        {
            Attributes instance = new Attributes();

            instance.AddAttribute(HeaderKeys.Algorithm, AlgorithmValues.AES_GCM_192, Attributes.PROTECTED);

            CBORObject cn;
            cn = instance.FindAttribute(HeaderKeys.Algorithm);
            Assert.AreEqual(cn, AlgorithmValues.AES_GCM_192);

            instance.RemoveAttribute(HeaderKeys.Algorithm);
            cn = instance.FindAttribute(HeaderKeys.Algorithm);
            Assert.AreEqual(cn, null);
        }

    }
}