using System;
using System.Collections;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities.Encoders;
using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public class JWK
    {
        readonly CBORObject _json;

        public JWK()
        {
            _json = CBORObject.NewMap();
        }

        public JWK(CBORObject jsonIn)
        {
            if (jsonIn.Type != CBORType.Map) throw new Exception("Invalid key structure");
            _json = jsonIn;
        }

        public BigInteger AsBigInteger(string key)
        {
            return ConvertBigNum(_json[key].AsString());
        }

        public byte[] AsBytes(string key)
        {
            return Message.base64urldecode(_json[key].AsString());
        }

        public string AsString(string key)
        {
            return _json[key].AsString();
        }

        public void Add(string key, string value)
        {
            _json.Add(key, CBORObject.FromObject(value));
        }

        public void Remove(string key)
        {
            _json.Remove(CBORObject.FromObject(key));
        }

        public Boolean ContainsName(string name)
        {
            return _json.ContainsKey(name);
        }

        public bool ContainsName(CBORObject obj)
        {
            return _json.ContainsKey(obj);
        }

        private static BigInteger ConvertBigNum(string str)
        {
            byte[] rgb = Message.base64urldecode(str);
            byte[] rgb2 = new byte[rgb.Length + 2];
            rgb2[0] = 0;
            rgb2[1] = 0;
            for (int i = 0; i < rgb.Length; i++) {
                rgb2[i + 2] = rgb[i];
            }

            return new BigInteger(rgb2);
        }

        public static byte[] FromBigNum(BigInteger bi)
        {
            byte[] rgbT = bi.ToByteArrayUnsigned();
            return rgbT;
        }

        public bool HasKeyType(string keyType)
        {
            if (_json.ContainsKey("kty") && _json["kty"].AsString() == keyType) {
                return true;
            }

            return false;
        }

        public bool HasKid(string kid)
        {
            return (_json.ContainsKey("kid") && _json["kid"].AsString() == kid);
        }

        public JWK PublicKey()
        {
            return new JWK(_json);
        }


        private AsymmetricKeyParameter PrivateKey { get; set; }

        public ICipherParameters AsPrivateKey()
        {
            if (PrivateKey != null) {
                return PrivateKey;
            }

            return null;
        }

        private AsymmetricKeyParameter PublicKeyX { get; set; }

        public ICipherParameters AsPublicKey()
        {
            if (PublicKeyX != null) {
                return PublicKeyX;
            }

            switch (_json["kty"].AsString()) {
            case "EC":
                X9ECParameters p = NistNamedCurves.GetByName(this.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                ECPoint point = p.Curve.CreatePoint(this.AsBigInteger("x"), this.AsBigInteger("y"));
                ECPublicKeyParameters pubKey = new ECPublicKeyParameters(point, parameters);
                PublicKeyX = pubKey;
                break;
            }


            return PublicKeyX;
        }

        public CBORObject ToJSON()
        {
            return _json;
        }

        public static JWK GenerateKey(string algorithm = null, string parameters = null)
        {
            if (algorithm != null) {
                switch (algorithm) {
                    case "A128GCM":
                        return GenerateOctetKey(algorithm, 128, parameters);

                    case "A256GCM":
                case "HS256":
                    return GenerateOctetKey(algorithm, 256, parameters);

                default:
                    throw new ArgumentException($"Unrecognized algorithm '{algorithm}'");
                }


            }

            throw new ArgumentException("NYI");
        }

        private static JWK GenerateOctetKey(string algorithm, int bits, string parameters)
        {
            CBORObject jwk = CBORObject.NewMap();
            jwk.Add("kty", "oct");
            jwk.Add("alg", algorithm);
            byte[] key = new byte[bits / 8];
            Message.s_PRNG.NextBytes(key, 0, key.Length);
            jwk.Add("k", Base64.ToBase64String(key));

            return new JWK(jwk);
        }


        public byte[] ComputeMac(byte[] toBeMaced)
        {
            if (!_json.ContainsKey("alg")) {
                throw new ArgumentException("Need to have an algorithm in order to MAC something");
            }

            string alg = _json["alg"].AsString();
            switch (alg) {
            case "HS256":
            case "HS384":
            case "HS512":
                return ComputeMac(toBeMaced, alg);

            default:
                throw new ArgumentException("Not a MAC key");
            }
        }

        public bool ValidateMac(byte[] toBeMaced, byte[] macValue)
        {
            if (!_json.ContainsKey("alg")) {
                throw new ArgumentException("Need to have an algorithm in order to MAC something");
            }

            string alg = _json["alg"].AsString();
            switch (alg) {
            case "HS256":
            case "HS384":
            case "HS512":
                return ValidateMac(toBeMaced, macValue, alg);

            default:
                throw new ArgumentException("Not a MAC key");
            }

        }

        internal byte[] ComputeMac(byte[] bytesToBeSigned, string alg)
        {
            IDigest digest;
            IDigest digest2;
            byte[] signature;

            switch (alg) {
            case "RS256":
            case "ES256":
            case "PS256":
            case "HS256":
                digest = new Sha256Digest();
                digest2 = new Sha256Digest();
                break;

            case "RS384":
            case "ES384":
            case "PS384":
            case "HS384":
                digest = new Sha384Digest();
                digest2 = new Sha384Digest();
                break;

            case "RS512":
            case "ES512":
            case "PS512":
            case "HS512":
                digest = new Sha512Digest();
                digest2 = new Sha512Digest();
                break;

            case "EdDSA":
                digest = null;
                digest2 = null;
                break;

            default:
                throw new JoseException("Unknown signature algorithm");
            }


            switch (alg) {
            case "RS256":
            case "RS384":
            case "RS512": {
                RsaDigestSigner signer = new RsaDigestSigner(digest);
                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(ConvertBigNum(this.AsString("n")),
                    ConvertBigNum(this.AsString("e")),
                    ConvertBigNum(this.AsString("d")),
                    ConvertBigNum(this.AsString("p")),
                    ConvertBigNum(this.AsString("q")),
                    ConvertBigNum(this.AsString("dp")),
                    ConvertBigNum(this.AsString("dq")),
                    ConvertBigNum(this.AsString("qi")));

                signer.Init(true, prv);
                signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                return signer.GenerateSignature();
            }

            case "PS256":
            case "PS384":
            case "PS512": {
                PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest.GetDigestSize());

                RsaKeyParameters prv = new RsaPrivateCrtKeyParameters(ConvertBigNum(this.AsString("n")),
                    ConvertBigNum(this.AsString("e")),
                    ConvertBigNum(this.AsString("d")),
                    ConvertBigNum(this.AsString("p")),
                    ConvertBigNum(this.AsString("q")),
                    ConvertBigNum(this.AsString("dp")),
                    ConvertBigNum(this.AsString("dq")),
                    ConvertBigNum(this.AsString("qi")));
                ParametersWithRandom rnd = new ParametersWithRandom(prv, Message.s_PRNG);

                signer.Init(true, rnd);
                signer.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                return signer.GenerateSignature();
            }

            case "ES256":
            case "ES384":
            case "ES512": {
                digest.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                byte[] o1 = new byte[digest.GetDigestSize()];
                digest.DoFinal(o1, 0);

                X9ECParameters p = NistNamedCurves.GetByName(this.AsString("crv"));
                ECDomainParameters parameters = new ECDomainParameters(p.Curve, p.G, p.N, p.H);
                ECPrivateKeyParameters privKey =
                    new ECPrivateKeyParameters("ECDSA", ConvertBigNum(this.AsString("d")), parameters);
                ParametersWithRandom param = new ParametersWithRandom(privKey, Message.s_PRNG);

                ECDsaSigner ecdsa = new ECDsaSigner(new HMacDsaKCalculator(new Sha256Digest()));
                ecdsa.Init(true, param);


                BigInteger[] sig = ecdsa.GenerateSignature(o1);
                byte[] r = sig[0].ToByteArrayUnsigned();
                byte[] s = sig[1].ToByteArrayUnsigned();

                int cbR = (p.Curve.FieldSize + 7) / 8;

                byte[] sigs = new byte[cbR * 2];
                Array.Copy(r, 0, sigs, cbR - r.Length, r.Length);
                Array.Copy(s, 0, sigs, cbR + cbR - s.Length, s.Length);

                signature = sigs;
                return sigs;
            }

            case "HS256":
            case "HS384":
            case "HS512": {
                HMac hmac = new HMac(digest);

                KeyParameter key = new KeyParameter(this.AsBytes("k"));
                byte[] resBuf = new byte[hmac.GetMacSize()];

                hmac.Init(key);
                hmac.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);
                hmac.DoFinal(resBuf, 0);

                signature = resBuf;
                return resBuf;
            }

            case "EdDSA":
                switch (this.AsString("crv")) {
                case "Ed25519": {
                    ISigner eddsa;
                    Ed25519PrivateKeyParameters privKey =
                        new Ed25519PrivateKeyParameters(this.AsBytes("d"), 0);
                    eddsa = new Ed25519Signer();
                    eddsa.Init(true, privKey);


                    eddsa.BlockUpdate(bytesToBeSigned, 0, bytesToBeSigned.Length);

                    signature = eddsa.GenerateSignature();
                    return signature;
                }
                }

                break;
            }

            return null;

        }

        internal bool ValidateMac(byte[] toBeSigned, byte[] signature, string alg)
        {
            IDigest digest;
            IDigest digest2;

            switch (alg) {
            case "RS256":
            case "ES256":
            case "PS256":
            case "HS256":
                digest = new Sha256Digest();
                digest2 = new Sha256Digest();
                break;

            case "RS384":
            case "ES384":
            case "PS384":
            case "HS384":
                digest = new Sha384Digest();
                digest2 = new Sha384Digest();
                break;

            case "RS512":
            case "ES512":
            case "PS512":
            case "HS512":
                digest = new Sha512Digest();
                digest2 = new Sha512Digest();
                break;

            case "EdDSA":
                digest = null;
                digest2 = null;
                break;

            default:
                throw new JoseException("Unknown signature algorithm");
            }


            switch (alg) {
            case "RS256":
            case "RS384":
            case "RS512": {
                if (this.AsString("kty") != "RSA") throw new JoseException("Wrong Key");
                RsaDigestSigner signer = new RsaDigestSigner(digest);
                RsaKeyParameters pub = new RsaKeyParameters(false, this.AsBigInteger("n"), this.AsBigInteger("e"));

                signer.Init(false, pub);
                signer.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                if (!signer.VerifySignature(signature)) throw new JoseException("Message failed to verify");

            }
                break;

            case "PS256":
            case "PS384":
            case "PS512": {
                PssSigner signer = new PssSigner(new RsaEngine(), digest, digest2, digest2.GetDigestSize());
                RsaKeyParameters pub = new RsaKeyParameters(false, this.AsBigInteger("n"), this.AsBigInteger("e"));

                signer.Init(false, pub);
                signer.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                if (!signer.VerifySignature(signature)) throw new JoseException("Message failed to verify");
            }

                break;

            case "ES256":
            case "ES384":
            case "ES512": {
                digest.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                byte[] o1 = new byte[digest.GetDigestSize()];
                digest.DoFinal(o1, 0);

                if (this.AsString("kty") != "EC") throw new JoseException("Wrong Key Type");

                ICipherParameters pubKey = this.AsPublicKey();
                ECDsaSigner ecdsa = new ECDsaSigner();
                ecdsa.Init(false, pubKey);

                BigInteger r = new BigInteger(1, signature, 0, signature.Length / 2);
                BigInteger s = new BigInteger(1, signature, signature.Length / 2, signature.Length / 2);

                if (!ecdsa.VerifySignature(o1, r, s)) throw new JoseException("Signature did not validate");
            }
                break;

            case "HS256":
            case "HS384":
            case "HS512": {
                HMac hmac = new HMac(digest);
                KeyParameter K = new KeyParameter(Message.base64urldecode(this.AsString("k")));
                hmac.Init(K);
                hmac.BlockUpdate(toBeSigned, 0, toBeSigned.Length);

                byte[] resBuf = new byte[hmac.GetMacSize()];
                hmac.DoFinal(resBuf, 0);

                bool fVerify = true;
                for (int i = 0; i < resBuf.Length; i++) {
                    if (resBuf[i] != signature[i]) {
                        fVerify = false;
                    }
                }

                if (!fVerify) throw new JoseException("Signature did not validate");
            }
                break;

            case "EdDSA": {
                ISigner eddsa;
                if (this.AsString("kty") != "OKP") throw new JoseException("Wrong Key Type");
                switch (this.AsString("crv")) {
                case "Ed25519": {
                    Ed25519PublicKeyParameters privKey =
                        new Ed25519PublicKeyParameters(this.AsBytes("X"), 0);
                    eddsa = new Ed25519Signer();
                    eddsa.Init(false, privKey);

                    eddsa.BlockUpdate(toBeSigned, 0, toBeSigned.Length);
                    if (!eddsa.VerifySignature(signature)) throw new JoseException("Signature did not validate");

                    break;
                }

                default:
                    throw new JoseException("Unknown algorithm");
                }

                break;
            }

            default:
                throw new JoseException("Unknown algorithm");
            }

            return true;
        }


    }

    public class JwkSet : IEnumerable<JWK>
    {
        readonly List<JWK> _keys = new List<JWK>();

        public JwkSet()
        {
            
        }

        public JwkSet(CBORObject json)
        {
            if (json.Type == CBORType.Array) {
                for (int i = 0; i < json.Count; i++) { _keys.Add(new JWK(json[i])); }
            }
            else {
                _keys.Add(new JWK(json));
            }
        }

        public JWK this[int i] => _keys[i];

        public void Add(JWK newKey) 
        {
            _keys.Add(newKey);
        }

        public int Count => _keys.Count;

        /// <inheritdoc />
        public IEnumerator<JWK> GetEnumerator()
        {
            return _keys.GetEnumerator();
        }

        /// <inheritdoc />
        IEnumerator IEnumerable.GetEnumerator()
        {
            return GetEnumerator();
        }
    }
}
