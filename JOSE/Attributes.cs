using System;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public class Attributes
    {
        private  CBORObject _objProtected = CBORObject.NewMap();
        private  CBORObject _objUnprotected = CBORObject.NewMap();
        private readonly CBORObject _objDontSend = CBORObject.NewMap();
        private byte[] _rgbProtected;

        /// <summary>
        /// The attribute is to be placed in the PROTECTED bucket.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public const int PROTECTED = 1;

        /// <summary>
        /// The attribute is to be placed in the UNPROTECTED bucket.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public const int UNPROTECTED = 2;

        /// <summary>
        /// The attribute is to be placed in the DO NOT SEND bucket.
        /// These values are available to the code with out being encoded into the final result.
        /// </summary>
        // ReSharper disable once InconsistentNaming
        public const int DO_NOT_SEND = 4;

        protected bool forceAsArray = false;

        internal CBORObject ProtectedMap {
            get => _objProtected;
            set => _objProtected = value;
        }

        protected byte[] ProtectedBytes {
            get => _rgbProtected;
            set => _rgbProtected = value;
        }

        internal CBORObject UnprotectedMap {
            get => _objUnprotected;
            set => _objUnprotected = value;
        }

        protected CBORObject DontSendMap {
            get => _objDontSend;
        }

        public void AddAttribute(string name, string value, bool fProtected)
        {
            AddAttribute(CBORObject.FromObject(name), CBORObject.FromObject(value), fProtected ? PROTECTED : UNPROTECTED);
        }

        public void AddAttribute(string name, string value, int where)
        {
            AddAttribute(CBORObject.FromObject(name), CBORObject.FromObject(value), where);
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
            if ((label.Type != CBORType.Integer) && (label.Type != CBORType.TextString))
            {
                throw new JoseException("Labels must be integers or strings");
            }
            switch (bucket)
            {
            case 1:
                if (_rgbProtected != null) throw new JoseException("Operation would modify integrity protected attributes");
                RemoveAttribute(label);
                _objProtected.Add(label, value);
                break;

            case 2:
                RemoveAttribute(label);
                _objUnprotected.Add(label, value);
                break;

            case 4:
                RemoveAttribute(label);
                _objDontSend.Add(label, value);
                break;

            default:
                throw new JoseException("Invalid attribute location given");
            }
        }

        /// <summary>
        /// Set an attribute value on a COSE object.  The attribute will be removed from any other buckets
        /// where it is currently placed.
        /// </summary>
        /// <param name="label">Label to be used for the attribute</param>
        /// <param name="value">Value to be used for the attribute</param>
        /// <param name="bucket">Which bucket is the attribute placed in?</param>
        public void AddAttribute(string name, CBORObject value, int where)
        {
            AddAttribute(CBORObject.FromObject(name), value, where);
        }

        [Obsolete("Use AddAttribute(string, CBORObject, int)")]
        public void AddAttribute(string name, CBORObject value, bool fProtected)
        {
            AddAttribute(CBORObject.FromObject(name), value, fProtected ? PROTECTED : UNPROTECTED);
        }

        [Obsolete("Use AddAttribute")]
        public void AddProtected(string name, string value)
        {
            AddAttribute(name, CBORObject.FromObject(value), PROTECTED);
        }

        [Obsolete("Use AddAttribute")]
        public void AddProtected(string name, CBORObject value)
        {
            AddAttribute(name, value, PROTECTED);
        }

        [Obsolete("Use AddAttribute")]
        public void AddUnprotected(string name, string value)
        {
            AddUnprotected(name, CBORObject.FromObject(value));
        }

        [Obsolete("Use AddAttribute")]
        public void AddUnprotected(string name, CBORObject value)
        {
            AddAttribute(name, value, UNPROTECTED);
        }

#if false
            public byte[] EncodeProtected()
            {
                byte[] A = new byte[0];
                if (objProtected != null) A = objProtected.EncodeToBytes();
                return A;
            }
#endif


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
            if (((where & PROTECTED) != 0) && _objProtected.ContainsKey(label)) return _objProtected[label];
            if (((where & UNPROTECTED) != 0) && _objUnprotected.ContainsKey(label)) return _objUnprotected[label];
            if (((where & DO_NOT_SEND) != 0) && _objDontSend.ContainsKey(label)) return _objDontSend[label];
            return null;
        }

        public CBORObject FindAttribute(CBORObject label)
        {
            return FindAttribute(label, PROTECTED + UNPROTECTED + DO_NOT_SEND);
        }

        public CBORObject FindAttribute(string name)
        {
            return FindAttribute(CBORObject.FromObject(name), PROTECTED + UNPROTECTED + DO_NOT_SEND);
        }

        [Obsolete("Use FindAttribute(name, PROTECTED/UNPROTECTED)")]
        public CBORObject FindAttribute(string name, bool fProtected)
        {
            return FindAttribute(CBORObject.FromObject(name), fProtected ? PROTECTED : UNPROTECTED);
        }

        //[Obsolete("Should you use this function?")]
        public CBORObject FindAttr(string key, Attributes msg)
        {
            CBORObject j = FindAttribute(key);
            if ((j == null) && (msg != null)) j = msg.FindAttribute(key);
            return j;
        }

        /// <summary>
        /// Remove a label from all buckets in the JOSE object.
        /// </summary>
        /// <param name="label">attribute to remove</param>
        public void RemoveAttribute(CBORObject label)
        {
            if (_objProtected.ContainsKey(label)) _objProtected.Remove(label);
            if (_objUnprotected.ContainsKey(label)) _objUnprotected.Remove(label);
            if (_objDontSend.ContainsKey(label)) _objDontSend.Remove(label);
        }


        public void ForceArray(bool f) { forceAsArray = f; }
        public void ClearProtected() { _objProtected.Clear();}

        public void ClearUnprotected() { _objUnprotected.Clear(); }
    }
}
