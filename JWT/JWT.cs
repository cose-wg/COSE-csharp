using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JOSE = Com.AugustCellars.JOSE;
using Com.AugustCellars.JOSE;
using PeterO.Cbor;

namespace Com.AugustCellars.JWT
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

    public class JWT
    {
        readonly CBORObject _claims = CBORObject.NewMap();

        public JWT()
        {

        }

        public JWT(CBORObject token)
        {
            if (token.Type != CBORType.Map) throw new JwtException("CWT must be a map");
            _claims = token;
        }



        public void SetClaim(ClaimID claim, string value)
        {
            SetClaim(claim, CBORObject.FromObject(value));
        }

        public void SetClaim(ClaimID claim, DateTime dt)
        {
            double unixTime = (TimeZoneInfo.ConvertTimeToUtc(dt) -
                       new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalSeconds;
            CBORObject value = CBORObject.FromObject(unixTime);
            SetClaim(claim, value);
        }

        public void SetClaim(ClaimID claim, CBORObject value)
        {
            string keyName;

            switch (claim) {
            case ClaimID.Issuer: keyName = "iss"; break;
            case ClaimID.Subject: keyName = "sub"; break;
            case ClaimID.Audience: keyName = "aud"; break;
            case ClaimID.ExpirationTime: keyName = "exp"; break;
            case ClaimID.NotBefore: keyName = "nbf"; break;
            case ClaimID.IssuedAt: keyName = "iat"; break;
            case ClaimID.CWTId: keyName = "jti"; break;

            default:
                throw new JwtException("Unknown claim ID");
            }
            SetClaim(keyName, value);
        }

        public void SetClaim(string claim, CBORObject value)
        {
            switch (claim) {
            case "iss":
            case "sub":
            case "aud":
                if (value.Type != CBORType.TextString) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            case "exp":
            case "nbf":
            case "iat":
                if (value.Type != CBORType.Integer) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            case "jti":
                if (value.Type != CBORType.TextString) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            default:
                //  We don't know how to check this
                break;
            }

            _claims.Add(claim, value);
        }
    }

}

