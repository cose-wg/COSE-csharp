
using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    public class Attributes
    {
        protected CBORObject objProtected = CBORObject.NewMap();
        protected CBORObject objUnprotected = CBORObject.NewMap();
        protected CBORObject objDontSend = CBORObject.NewMap();
        protected byte[] externalData = new byte[0];
        protected byte[] _rgbProtected;

        static public int PROTECTED = 1;
        static public int UNPROTECTED = 2;
        static public int DO_NOT_SEND = 4;

        /// <summary>
        /// Set an attribute value on a COSE object.  The attribute will be removed from any other buckets
        /// where it is currently placed.
        /// </summary>
        /// <param name="label">Label to be used for the attribute</param>
        /// <param name="value">Value to be used for the attribute</param>
        /// <param name="bucket">Which bucket is the attribute placed in?</param>
        public void AddAttribute(string label, string value, int bucket)
        {
            AddAttribute(CBORObject.FromObject(label), CBORObject.FromObject(value), bucket);
        }

        /// <summary>
        /// Set an attribute value on a COSE object.  The attribute will be removed from any other buckets
        /// where it is currently placed.
        /// </summary>
        /// <param name="label">Label to be used for the attribute</param>
        /// <param name="value">Value to be used for the attribute</param>
        /// <param name="bucket">Which bucket is the attribute placed in?</param>
        public void AddAttribute(string label, CBORObject value, int bucket)
        {
            AddAttribute(CBORObject.FromObject(label), value, bucket);
        }

        /// <summary>
        /// Set an attribute value on a COSE object.  The attribute will be removed from any other buckets
        /// where it is currently placed.
        /// </summary>
        /// <param name="label">Label to be used for the attribute</param>
        /// <param name="value">Value to be used for the attribute</param>
        /// <param name="bucket">Which bucket is the attribute placed in?</param>
        public void AddAttribute(CBORObject label, CBORObject value, int bucket)
        { 
            if ((label.Type != CBORType.Number) && (label.Type != CBORType.TextString))
            {
                throw new CoseException("Labels must be integers or strings");
            }
            switch (bucket) {
                case 1:
                    if (_rgbProtected != null) throw new CoseException("Operation would modify integrity protected attributes");
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

        /// <summary>
        /// Locate an attribute.  All of the buckets in the message are searched.
        /// They are searched in the order - Protected, Unprotected, Don't Send.
        /// </summary>
        /// <param name="label">label of attribute to search for </param>
        /// <returns></returns>
        public CBORObject FindAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) return objProtected[label];
            if (objUnprotected.ContainsKey(label)) return objUnprotected[label];
            if (objDontSend.ContainsKey(label)) return objDontSend[label];
            return null;
        }

        /// <summary>
        /// Locate an attribute.  All of the buckets in the message are searched.
        /// They are searched in the order - Protected, Unprotected, Don't Send.
        /// </summary>
        /// <param name="label">label of attribute to search for </param>
        /// <returns></returns>
        public CBORObject FindAttribute(int label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        /// <summary>
        /// Locate an attribute.  All of the buckets in the message are searched.
        /// They are searched in the order - Protected, Unprotected, Don't Send.
        /// </summary>
        /// <param name="label">label of attribute to search for </param>
        /// <returns></returns>
        public CBORObject FindAttribute(string label)
        {
            return FindAttribute(CBORObject.FromObject(label));
        }

        /// <summary>
        /// Locate an attribute.  All of the buckets in the message are searched.
        /// Multiple buckets can be searched by or-ing together the bucket identifiers.
        /// They are searched in the order - Protected, Unprotected, Don't Send.
        /// </summary>
        /// <param name="label">label of attribute to search for </param>
        /// <param name="where">location(s) to be searched</param>
        /// <returns></returns>
        public CBORObject FindAttribute(CBORObject label, int where)
        {
            if (((where & PROTECTED) != 0) && objProtected.ContainsKey(label)) return objProtected[label];
            if (((where & UNPROTECTED) != 0) && objUnprotected.ContainsKey(label)) return objUnprotected[label];
            if (((where & DO_NOT_SEND) != 0) && objDontSend.ContainsKey(label)) return objDontSend[label];
            return null;
        }

        /// <summary>
        /// Remove a label from all buckets in the COSE object.
        /// </summary>
        /// <param name="label">attribute to remove</param>
        public void RemoveAttribute(CBORObject label)
        {
            if (objProtected.ContainsKey(label)) objProtected.Remove(label);
            if (objUnprotected.ContainsKey(label)) objUnprotected.Remove(label);
            if (objDontSend.ContainsKey(label)) objDontSend.Remove(label);
        }

        /// <summary>
        /// Set the external data to be included in the cryptographic computation for the COSE object.
        /// </summary>
        /// <param name="newData">external data to be used</param>
        public void SetExternalData(byte[] newData)
        {
            externalData = newData;
        }
    }
}
