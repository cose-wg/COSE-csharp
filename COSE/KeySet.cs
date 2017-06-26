using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Security;
using PeterO.Cbor;

namespace Com.AugustCellars.COSE
{
    /// <summary>
    /// The KeySet class allows for a collection of keys to be dealt with.
    /// The class can be serialized, parsed and filtered.
    /// </summary>
    public class KeySet
    {
        List<OneKey> _keyList = new List<OneKey>();

        /// <summary>
        /// Return number of keys in the key set.
        /// </summary>
        public int Count {
            get { return _keyList.Count; }
        }

        /// <summary>
        /// Return first key in the set.
        /// </summary>
        public OneKey FirstKey {
            get { return _keyList.First(); }
        }

        /// <summary>
        /// Return the i-th element in the key set.
        /// </summary>
        /// <param name="i">index of element to return</param>
        /// <returns>OneKey</returns>
        public OneKey this[int i] {
            get { return _keyList[i]; }
        }

        /// <summary>
        /// Default constructor creates a new KeySet object with no keys in it.
        /// </summary>
        public KeySet()
        {
            
        }

        /// <summary>
        /// Constructor takes a CBOR Array and treats each element as a key to be added to the key set.
        /// </summary>
        /// <param name="obj"></param>
        public KeySet(CBORObject obj)
        {
            if (obj.Type != CBORType.Array) throw new InvalidParameterException("obj must be a CBOR array");
            foreach (var cborObject in obj.Values) {
                OneKey key = new OneKey(cborObject);
                AddKey(key);
            }
        }

        /// <summary>
        /// Add a key to the key set.  The function will do a minimal check for equality to existing keys in the set.
        /// </summary>
        /// <param name="key">OneKey: key to be added</param>
        public void AddKey(OneKey key)
        {
            foreach (OneKey k in _keyList) {
                if (key.Compare(k))
                    return;
            }
            _keyList.Add(key);
        }

        /// <summary>
        /// Remove the given key from the list if it is on it.
        /// </summary>
        /// <param name="key"></param>
        public void RemoveKey(OneKey key)
        {
            _keyList.Remove(key);
        }

        /// <summary>
        /// Encode the set of keys in the key set as a CBOR object
        /// </summary>
        /// <returns></returns>
        public CBORObject AsCBOR()
        {
            CBORObject obj = CBORObject.NewArray();

            foreach (OneKey key in _keyList) {
                obj.Add(key.AsCBOR());
            }
            return obj;
        }

        /// <summary>
        /// Encode the set of keys as a CBOR object and then encode that into a byte string
        /// </summary>
        /// <returns>byte array</returns>
        public byte[] EncodeToBytes()
        {
            return AsCBOR().EncodeToBytes();
        }


        /// <summary>
        /// All forall to be used to enumerate the keys in a key set.
        /// </summary>
        /// <returns></returns>
        public IEnumerator<OneKey> GetEnumerator()
        {
            return _keyList.GetEnumerator();
        }

        /// <summary>
        /// Apply a filter to a key set to retrieve keys which match a speciic criteria.
        /// </summary>
        /// <param name="lambda">Function which returns true for the desired keys</param>
        /// <returns>New key set with all functions</returns>
        public KeySet Where(Func<OneKey, bool> lambda)
        {
            KeySet ks = new KeySet();
            ks._keyList = _keyList.Where(lambda).ToList();
            return ks;
        }

    }
}
