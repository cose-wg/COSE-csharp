using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class Attributes
    {
        protected CBORObject objProtected = CBORObject.NewMap();
        protected CBORObject objUnprotected = CBORObject.NewMap();
        protected CBORObject objDontSend = CBORObject.NewMap();
        protected byte[] externalData = new byte[0];
        protected byte[] rgbProtected;

        static public int PROTECTED = 1;
        static public int UNPROTECTED = 2;
        static public int DO_NOT_SEND = 4;

        public void AddAttribute(string name, string value, int bucket)
        {
            AddAttribute(CBORObject.FromObject(name), CBORObject.FromObject(value), bucket);
        }

        public void AddAttribute(string name, CBORObject value, int bucket)
        {
            AddAttribute(CBORObject.FromObject(name), value, bucket);
        }

        public void AddAttribute(CBORObject label, CBORObject value, int bucket)
        { 
            if ((label.Type != CBORType.Number) && (label.Type != CBORType.TextString))
            {
                throw new CoseException("Labels must be integers or strings");
            }
            switch (bucket) {
                case 1:
                    if (rgbProtected != null) throw new CoseException("Operation would modify integrity protected attributes");
                    RemoveAttribute(label);
                    objProtected.Add(label, value);
                    break;

                case 2:
                    RemoveAttribute(label);
                    objUnprotected.Add(label, value);
                    break;

                case 4:
                    RemoveAttribute(label);
                    objDontSend.Add(label, value);
                    break;

                default:
                    throw new CoseException("Invalid attribute location given");
            }
        }

        [System.Obsolete("Use AddAttribute(string, string, Attributes.Protected")]
        public void AddAttribute(string name, string value, bool fProtected)
        {
            AddAttribute(name, value, fProtected ? PROTECTED : UNPROTECTED);
        }

        [System.Obsolete("Use AddAttribute(string, CBORObject, Attributes.Protected")]
        public void AddAttribute(string name, CBORObject value, bool fProtected)
        {
            AddAttribute(name, value, fProtected ? PROTECTED : UNPROTECTED);
        }

        [System.Obsolete("Use AddAttribute(key, value, Attributes.Protected)")]
        public void AddAttribute(CBORObject key, CBORObject value, bool fProtected)
        {
            if (fProtected) AddProtected(key, value);
            else AddUnprotected(key, value);
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Protected)")]
        public void AddProtected(string label, string value)
        {
            AddProtected(label, CBORObject.FromObject(value));
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Protected)")]
        public void AddProtected(string label, CBORObject value)
        {
            AddProtected(CBORObject.FromObject(label), value);
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Unprotected)")]
        public void AddUnprotected(string label, string value)
        {
            AddUnprotected(label, CBORObject.FromObject(label));
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Unprotected)")]
        public void AddUnprotected(string label, CBORObject value)
        {
            AddUnprotected(CBORObject.FromObject(label), value);
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Protected)")]
        public void AddProtected(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objProtected.Add(label, value);
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.Unprotected)")]
        public void AddUnprotected(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objUnprotected.Add(label, value);
        }

        [System.Obsolete("Use AddAttribue(label, value, Attributes.DoNotSend)")]
        public void AddDontSend(CBORObject label, CBORObject value)
        {
            RemoveAttribute(label);
            objDontSend.Add(label, value);
        }

        public CBORObject FindAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) return objProtected[label];
            if (objUnprotected.ContainsKey(label)) return objUnprotected[label];
            if (objDontSend.ContainsKey(label)) return objDontSend[label];
            return null;
        }

        public CBORObject FindAttribute(int label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        public CBORObject FindAttribute(string label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        public CBORObject FindAttribute(CBORObject label, int where)
        {
            if (((where & PROTECTED) != 0) && objProtected.ContainsKey(label)) return objProtected[label];
            if (((where & UNPROTECTED) != 0) && objUnprotected.ContainsKey(label)) return objUnprotected[label];
            if (((where & DO_NOT_SEND) != 0) && objDontSend.ContainsKey(label)) return objDontSend[label];
            return null;
        }

        public void RemoveAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) objProtected.Remove(label);
            if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
            if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
        }

        public void SetExternalData(byte[] newData)
        {
            externalData = newData;
        }
    }
}
