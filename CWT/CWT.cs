using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Com.AugustCellars.COSE;
using PeterO.Cbor;

namespace CWT
{
    public enum ClaimId
    {
        Issuer = 1,
        Subject = 2,
        Audience = 3,
        ExpirationTime = 4,
        NotBefore = 5,
        IssuedAt = 6,
        CwtId = 7,
        Cnf = 9999,

}

public class CborWebToken
    {
        CBORObject claims = CBORObject.NewMap();

        private static readonly CBORObject _TagProfile = CBORObject.FromObject("profile");

        public CborWebToken()
        {

        }

        public CborWebToken(CBORObject cbor)
        {
            if (cbor.Type != CBORType.Map) throw new CwtException("CWT must be a map");
            claims = cbor;
        }

        public ICollection<CBORObject> AllClaimKeys
        {
            get => claims.Keys;
        }

        public String Audience
        {
            get => claims[CBORObject.FromObject(ClaimId.Audience)].AsString();
            set => claims.Add(CBORObject.FromObject(ClaimId.Audience), value);
        }

        public Confirmation Cnf
        {
            get => new Confirmation(claims[CBORObject.FromObject(ClaimId.Cnf)]);
            set => claims.Add((int) ClaimId.Cnf, value.AsCBOR);
        }

        public string Profile
        {
            get => claims.ContainsKey(_TagProfile) ? claims[_TagProfile].AsString() : null;
            set => claims.Add(_TagProfile, value);
        }

        public bool HasClaim(ClaimId claimId)
        {
            return claims.ContainsKey(CBORObject.FromObject(claimId));
        }

        public CBORObject GetClaim(CBORObject claimKey)
        {
            return claims[claimKey];
        }

        public void SetClaim(ClaimId claim, string value)
        {
            SetClaim(claim, CBORObject.FromObject(value));
        }

        public void SetClaim(ClaimId claim, DateTime dt)
        {
            double unixTime = (TimeZoneInfo.ConvertTimeToUtc(dt) -
                       new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
            CBORObject value = CBORObject.FromObject((long) unixTime);
            value = CBORObject.FromObjectAndTag(value, 1);
            SetClaim(claim, value);
        }

        public void SetClaim(ClaimId claim, CBORObject value)
        {
            SetClaim(CBORObject.FromObject((Int32) claim), value);
        }

        public void SetClaim(CBORObject claim, CBORObject value)
        {
            switch ((ClaimId) claim.AsInt32()) {
            case ClaimId.Issuer:
            case ClaimId.Subject:
            case ClaimId.Audience:
                if (value.Type != CBORType.TextString) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            case ClaimId.ExpirationTime:
            case ClaimId.NotBefore:
            case ClaimId.IssuedAt:
                if (value.Type != CBORType.Number) throw new CwtException("Claim value type is incorrect for the claim");
                if (value.GetTags().Count() != 0) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            case ClaimId.CwtId:
                if (value.Type != CBORType.ByteString) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            default:
                //  We don't know how to check this
                break;
            }

            claims[claim] = value;
        }


        #region EncodingToken

        /// <summary>
        /// Get/Set the key for encrypting the token
        /// </summary>
        public OneKey EncryptionKey { get; set; }

        public byte[] EncodeToBytes()
        {
            if (EncryptionKey == null) throw new CwtException("Must either encrypt, Sign or MAC a CWT object");

            byte[] msgBytes = claims.EncodeToBytes();

            if (EncryptionKey != null) {
                Encrypt0Message enc = new Encrypt0Message();
                
                enc.AddAttribute(HeaderKeys.Algorithm, EncryptionKey[CoseKeyKeys.Algorithm],  Attributes.PROTECTED);
                enc.AddAttribute(HeaderKeys.KeyId, EncryptionKey[CoseKeyKeys.KeyIdentifier], Attributes.UNPROTECTED);
                enc.SetContent(msgBytes);

                enc.Encrypt(EncryptionKey[CoseKeyParameterKeys.Octet_k].GetByteString());

                msgBytes = enc.EncodeToBytes();
            }

            return msgBytes;
        }

        public static CborWebToken Decode(byte[] encodedToken, KeySet myDecryptKeySet, KeySet asSignKeySet)
        {
            return Decode(encodedToken, (data, coseObject) => KeysFromKeySet(myDecryptKeySet, coseObject));
        }

        public delegate IEnumerable<OneKey> FindKeys(Object appData, Attributes coseObject);

        private static IEnumerable<OneKey> KeysFromKeySet(Object appData, Attributes coseObject)
        {
            CBORObject kid = coseObject.FindAttribute(HeaderKeys.KeyId);
            CBORObject alg = coseObject.FindAttribute(HeaderKeys.Algorithm);
            KeySet keySet = (KeySet) appData;

            if (kid == null) yield break;

            foreach (OneKey key in keySet) {
                if (!key.HasKid(kid.GetByteString())) continue;


                yield return key;
            }

            yield break;
        }


        public static CborWebToken Decode(byte[] encodedToken, FindKeys getKeyFunction)
        {
            CBORObject cbor = CBORObject.DecodeFromBytes(encodedToken);
            OneKey encryptionKey = null;

            if (cbor.HasTag(9999)) {
                //  It would be nice to remove this but I don't see how to do it.
            }

            do {
                if (cbor.GetTags().Length != 1) throw new CwtException("Malformed CWT structure");

                Message msg = Message.DecodeFromCBOR(cbor);

                if (msg is Encrypt0Message) {
                    Encrypt0Message enc0 = (Encrypt0Message) msg;

                    if (encryptionKey != null) throw new CwtException("Multiple encryption nesting is not handled");

                    IEnumerable<OneKey> keys = getKeyFunction(null, enc0);

                    encodedToken = null;

                    foreach (OneKey testKey in keys) {
                        try {
                            encodedToken = enc0.Decrypt(testKey[CoseKeyParameterKeys.Octet_k].GetByteString());
                            encryptionKey = testKey;
                            break;
                        }
                        catch {
                            ;
                        }
                    }

                    if (encryptionKey == null) {
                        throw new CwtException("Failed to find a key to decrypt with");
                    }
                }

                cbor = CBORObject.DecodeFromBytes(encodedToken);

            } while (cbor.IsTagged);

            CborWebToken cwt = new CborWebToken(cbor) {
                EncryptionKey = encryptionKey
            };

            return cwt;
        }


        #endregion
    }
}
