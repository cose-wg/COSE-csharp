using System;
using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace CWT
{
    public class Confirmation
    {
        private readonly CBORObject _data = CBORObject.NewMap();

        /// <summary>
        /// Create empty confirmation object
        /// </summary>
        public Confirmation()
        {
            
        }

        /// <summary>
        /// Create conformation object from a CBOR object
        /// </summary>
        /// <param name="cbor"></param>
        public Confirmation(CBORObject cbor)
        {
            if (cbor.Type != CBORType.Map) throw new ArgumentException("Not a CBOR map");
            _data = cbor;
        }

        /// <summary>
        /// Create  conformation object from a key
        /// </summary>
        /// <param name="key"></param>
        public Confirmation(OneKey key)
        {
            _data.Add("COSE_Key", key.AsCBOR());
        }

        /// <summary>
        /// Get - Return the COSE_Key element as a key if it exists.
        /// Set - create the COSE_Key element from the key
        /// </summary>
        public OneKey Key
        {
            get
            {
                if (!_data.ContainsKey("COSE_Key")) return null;
                return new OneKey(_data["COSE_Key"]);
            }
            set => _data.Add("COSE_Key", value.AsCBOR());
        }

        /// <summary>
        /// Get - return the encrypted key block if it exists
        /// Set - set an encrypted key object
        /// </summary>
        public byte[] EncryptedKey
        {
            get
            {
                if (_data.ContainsKey("COSE_Encrypted")) return _data["COSE_Encrypted"].GetByteString();
                return null;
            }
            set => _data.Add("COSE_Encrypted", value);
        }

        public byte[] Kid
        {
            get
            {
                if (!_data.ContainsKey("Key Identifier")) return null;
                return _data["Key Identifier"].GetByteString();
            }
            set => _data.Add("Key Identifier", value);
        }

        public CBORObject AsCBOR
        {
            get =>  _data;
        }
    }
}
