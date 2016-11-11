using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using JOSE;

namespace JWT
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
        JOSE.JSON claims = new JSON();

        public JWT()
        {

        }

        public void SetClaim(ClaimID claim, string value)
        {
            SetClaim(claim, JSON.FromObject(value));
        }

        public void SetClaim(ClaimID claim, DateTime dt)
        {
            double unixTime = (TimeZoneInfo.ConvertTimeToUtc(dt) -
                       new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc)).TotalSeconds;
            JSON value = JSON.FromObject(unixTime);
            SetClaim(claim, value);
        }

        public void SetClaim(ClaimID claim, JSON value)
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

        public void SetClaim(string claim, JSON value)
        {
            switch (claim) {
            case "iss":
            case "sub":
            case "aud":
                if (value.nodeType != JsonType.text) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            case "exp":
            case "nbf":
            case "iat":
                if (value.nodeType != JsonType.number) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            case "jti":
                if (value.nodeType != JsonType.text) throw new JwtException("Claim value type is incorrect for the claim");
                break;

            default:
                //  We don't know how to check this
                break;
            }

            claims.Add(claim, value);
        }
    }

}

