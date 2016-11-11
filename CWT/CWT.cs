using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using PeterO.Cbor;

namespace CWT
{
    public enum ClaimID
    {
        Issuer = 1,
        Subject = 2,
        Audience = 3,
        ExpirationTime = 4,
        NotBefore = 5,
        IssuedAt = 6,
        CWTId = 7
    }
    public class CWT
    {
        CBORObject claims = CBORObject.NewMap();

        public CWT()
        {

        }

        public void SetClaim(ClaimID claim, string value)
        {
            SetClaim(claim, CBORObject.FromObject(value));
        }

        public void SetClaim(ClaimID claim, DateTime dt)
        {
            double unixTime = (TimeZoneInfo.ConvertTimeToUtc(dt) -
                       new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalSeconds;
            CBORObject value = CBORObject.FromObject((long) unixTime);
            value = CBORObject.FromObjectAndTag(value, 1);
            SetClaim(claim, value);
        }

        public void SetClaim(ClaimID claim, CBORObject value)
        {
            SetClaim(CBORObject.FromObject((Int32) claim), value);
        }

        public void SetClaim(CBORObject claim, CBORObject value)
        {
            switch ((ClaimID) claim.AsInt32()) {
            case ClaimID.Issuer:
            case ClaimID.Subject:
            case ClaimID.Audience:
                if (value.Type != CBORType.TextString) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            case ClaimID.ExpirationTime:
            case ClaimID.NotBefore:
            case ClaimID.IssuedAt:
                if (value.Type != CBORType.Number) throw new CwtException("Claim value type is incorrect for the claim");
                if ((value.GetTags().Count() != 1) || (value.OutermostTag.intValue() != 1)) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            case ClaimID.CWTId:
                if (value.Type != CBORType.ByteString) throw new CwtException("Claim value type is incorrect for the claim");
                break;

            default:
                //  We don't know how to check this
                break;
            }

            claims[claim] = value;
        }
    }
}
