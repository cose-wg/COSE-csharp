using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Asn1.X9;

using Org.BouncyCastle.Crypto.Digests;

namespace COSE
{
#if false
    public class CfrgCurves
    {
        static public X9ECParameters GetByName(string curveName)
        {
            switch (curveName) {
            case "X25519":
                return X25519Holder.Instance.Parameters;
            default:
                return null;
            }
        }

        private static ECCurve ConfigureCurve(ECCurve curve)
        {
            return curve;
        }


        internal class X25519Holder : X9ECParametersHolder
        {
            internal static readonly X9ECParametersHolder Instance = new X25519Holder();

            protected override X9ECParameters CreateParameters()
            {
                byte[] S = null;
                ECCurve curve = ConfigureCurve(new X25519());
                return new X9ECParameters(curve, g, curve.Order, curve.CoFacter, S);
            }
        }
    }
#endif

    public class X25519KeyPair
    {
        byte[] publicValue;
        byte[] privateValue;

        public byte[] Public { get { return publicValue; } }
        public byte[] Private { get { return privateValue; } }

        static readonly byte[] nine = new byte[] { 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

        static public X25519KeyPair GenerateKeyPair()
        {
            X25519KeyPair key = new X25519KeyPair();

            key.privateValue = new byte[32];
            Message.GetPRNG().NextBytes(key.privateValue);

            key.publicValue = X25519.CalculateAgreement(nine, key.privateValue);
            return key;
        }
    }

    public class CfrgCurve
    {
        public readonly int bits;
        public readonly BigInteger a24;
        public readonly BigInteger p;
        public delegate void Mask(byte[] key);
        public Mask maskFunction;

        public CfrgCurve(int bitsIn, BigInteger a24In, BigInteger pIn, Mask function)
        {
            bits = bitsIn;
            a24 = a24In;
            p = pIn;
            maskFunction = function;
        }

    }

    public class X448 : CfrgCurves
    {
        static readonly CfrgCurve crvData = new CfrgCurve(bits, a24, p, Mask);
        static readonly int bits = 448;
        static readonly BigInteger a24 = new BigInteger("39081");
        static readonly BigInteger p = new BigInteger("2").Pow(448).Subtract(new BigInteger("2").Pow(224)).Subtract(new BigInteger("1"));

        static public void Mask(byte[] key)
        {
            key[0] &= 252;
            key[55] |= 128;
        }

        static public byte[] CalculateAgreement(byte[] publicKey, byte[] privateKey)
        {
            byte[] tmp = new byte[privateKey.Length];
            Array.Copy(privateKey, tmp, privateKey.Length);
            Mask(tmp);
            Array.Reverse(tmp);
            BigInteger scalar = new BigInteger(1, tmp);

            tmp = new byte[publicKey.Length];
            Array.Copy(publicKey, tmp, publicKey.Length);
            Array.Reverse(tmp);
            BigInteger point = new BigInteger(1, tmp);

            BigInteger result = Compute(scalar, point, crvData);
            tmp = result.ToByteArrayUnsigned();
            Array.Reverse(tmp);

            return tmp;
        }

    }

    public class X25519 : CfrgCurves
    {
        static readonly BigInteger Nine = new BigInteger(new byte[] { 9 });
        static readonly int bits = 255;
        static readonly BigInteger a24 = new BigInteger("121665");
        static readonly BigInteger p = new BigInteger("2").Pow(255).Subtract(new BigInteger("19"));

        static readonly CfrgCurve crvData = new CfrgCurve(bits, a24, p, Mask);

        static public X25519KeyPair GenerateKeyPair()
        {
            return X25519KeyPair.GenerateKeyPair();
        }

        static public void Mask(byte[] key)
        {
            key[0] &= 248;
            key[31] &= 127;
            key[31] |= 64;

        }

        static public byte[] GetPublic(byte[] rgbPrivate)
        {
            byte[] X = new byte[rgbPrivate.Length];
            Array.Copy(rgbPrivate, X, rgbPrivate.Length);

            X[0] &= 248;
            X[31] &= 127;
            X[31] |= 64;
            Array.Reverse(X);
            BigInteger AlicePrivate = new BigInteger(1, X);

            BigInteger result = Compute(AlicePrivate, Nine, crvData);
            X = result.ToByteArrayUnsigned();
            Array.Reverse(X);
            return X;
        }


        static public void SelfTest()
        {
            BigInteger InputScalar = new BigInteger("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", 16);
            BigInteger InputU = new BigInteger("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", 16);
            BigInteger OutputU = new BigInteger("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552", 16);

            byte[] X = InputScalar.ToByteArrayUnsigned();
            Mask(X);
            Array.Reverse(X);
            InputScalar = new BigInteger(1, X);

            X = InputU.ToByteArrayUnsigned();
            Array.Reverse(X);
            InputU = new BigInteger(1, X);

            BigInteger result = Compute(InputScalar, InputU, crvData);
            X = result.ToByteArrayUnsigned();
            Array.Reverse(X);


            BigInteger AlicePrivate = new BigInteger("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a", 16);
            X = AlicePrivate.ToByteArrayUnsigned();
            X[0] &= 248;
            X[31] &= 127;
            X[31] |= 64;
            Array.Reverse(X);
            AlicePrivate = new BigInteger(1, X);

            result = Compute(AlicePrivate, Nine, crvData);
            X = result.ToByteArrayUnsigned();
            Array.Reverse(X);
        }



        static public byte[] CalculateAgreement(byte[] publicKey, byte[] privateKey)
        {
            byte[] tmp = new byte[privateKey.Length];
            Array.Copy(privateKey, tmp, privateKey.Length);
            Mask(tmp);
            Array.Reverse(tmp);
            BigInteger scalar = new BigInteger(1, tmp);

            tmp = new byte[publicKey.Length];
            Array.Copy(publicKey, tmp, publicKey.Length);
            Array.Reverse(tmp);
            BigInteger point = new BigInteger(1, tmp);

            BigInteger result = Compute(scalar, point, crvData);
            tmp = result.ToByteArrayUnsigned();
            Array.Reverse(tmp);

            return tmp;
        }

    }

    public class CfrgCurves
    {
        static readonly BigInteger Zero = new BigInteger(new byte[] { 0 });
        static readonly BigInteger One = new BigInteger(new byte[] { 1 });
        static readonly BigInteger Two = new BigInteger(new byte[] { 2 });

        static protected BigInteger Compute(BigInteger k, BigInteger u, CfrgCurve crv)
        {
            BigInteger x_1 = u;
            BigInteger x_2 = One;
            BigInteger z_2 = Zero;
            BigInteger x_3 = u;
            BigInteger z_3 = One;
            bool swap = false;

            for (int t = crv.bits - 1; t >= 0; t--) {
                bool k_t = k.TestBit(t);
                swap ^= k_t;
                // Conditional swap
                if (swap) {
                    BigInteger tmp;
                    tmp = x_2; x_2 = x_3; x_3 = tmp;
                    tmp = z_2; z_2 = z_3; z_3 = tmp;
                }
                swap = k_t;

                BigInteger A = x_2.Add(z_2).Mod(crv.p);
                BigInteger AA = A.Square().Mod(crv.p);
                BigInteger B = x_2.Subtract(z_2).Mod(crv.p);
                BigInteger BB = B.Square().Mod(crv.p);
                BigInteger E = AA.Subtract(BB).Mod(crv.p);
                BigInteger C = x_3.Add(z_3).Mod(crv.p);
                BigInteger D = x_3.Subtract(z_3).Mod(crv.p);
                BigInteger DA = D.Multiply(A).Mod(crv.p);
                BigInteger CB = C.Multiply(B).Mod(crv.p);
                x_3 = (DA.Add(CB)).Square().Mod(crv.p);
                z_3 = x_1.Multiply((DA.Subtract(CB)).Square()).Mod(crv.p);
                x_2 = AA.Multiply(BB).Mod(crv.p);
                z_2 = E.Multiply(AA.Add(crv.a24.Multiply(E))).Mod(crv.p);
            }

            if (swap) {
                BigInteger tmp;
                tmp = x_2; x_2 = x_3; x_3 = tmp;
                tmp = z_2; z_2 = z_3; z_3 = tmp;
            }

            return x_2.Multiply(z_2.ModPow(crv.p.Subtract(Two), crv.p)).Mod(crv.p);
        }

        static public byte[] CalculateAgreement(byte[] publicKey, byte[] privateKey, CfrgCurve crvData)
        {
            byte[] tmp = new byte[privateKey.Length];
            Array.Copy(privateKey, tmp, privateKey.Length);
            crvData.maskFunction(tmp);
            Array.Reverse(tmp);
            BigInteger scalar = new BigInteger(1, tmp);

            tmp = new byte[publicKey.Length];
            Array.Copy(publicKey, tmp, publicKey.Length);
            Array.Reverse(tmp);
            BigInteger point = new BigInteger(1, tmp);

            BigInteger result = Compute(scalar, point, crvData);
            tmp = result.ToByteArrayUnsigned();
            Array.Reverse(tmp);

            return tmp;
        }
    }

    public abstract class EdDSAPoint
    {
        readonly public static BigInteger zero = new BigInteger("0");
        readonly public static BigInteger one = new BigInteger("1");
        readonly public static BigInteger Two = new BigInteger("2");

        public BigInteger X;
        public BigInteger Y;
        public BigInteger Z;
        public BigInteger T;

        public abstract byte[] Encode();
        public abstract EdDSAPoint MultipleByScalar(BigInteger k);
        public abstract EdDSAPoint Normalize();

        public Boolean equal(EdDSAPoint other)
        {
            if (!this.X.Equals(other.X)) return false;
            if (!this.Y.Equals(other.Y)) return false;
            return true;
        }
    }

    public class EdDSAPoint25517 : EdDSAPoint
    {
        readonly static BigInteger p = Two.Pow(255).Subtract(new BigInteger("19"));
        readonly static BigInteger d = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");

        public readonly static EdDSAPoint25517 B =
            new EdDSAPoint25517(
                new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
                new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"),
                p);

        public EdDSAPoint25517(BigInteger xIn, BigInteger yIn, BigInteger pIn)
        {
            X = xIn;
            Y = yIn;
            T = xIn.Multiply(yIn).Mod(pIn);
            Z = one;
        }

        public EdDSAPoint25517(BigInteger xIn, BigInteger yIn, BigInteger zIn, BigInteger tIn)
        {
            X = xIn;
            Y = yIn;
            Z = zIn;
            T = tIn;
        }

        static public EdDSAPoint25517 Add(EdDSAPoint25517 p1, EdDSAPoint25517 p2)
        {
            BigInteger A = p1.Y.Subtract(p1.X).Multiply(p2.Y.Subtract(p2.X)).Mod(p);
            BigInteger B = p1.Y.Add(p1.X).Multiply(p2.Y.Add(p2.X)).Mod(p);
            BigInteger C = p1.T.Multiply(Two).Multiply(d).Multiply(p2.T).Mod(p);
            BigInteger D = p1.Z.Multiply(Two).Multiply(p2.Z).Mod(p);
            BigInteger E = B.Subtract(A).Mod(p);
            BigInteger F = D.Subtract(C).Mod(p);
            BigInteger G = D.Add(C).Mod(p);
            BigInteger H = B.Add(A).Mod(p);
            BigInteger X3 = E.Multiply(F).Mod(p);
            BigInteger Y3 = G.Multiply(H).Mod(p);
            BigInteger T3 = E.Multiply(H).Mod(p);
            BigInteger Z3 = F.Multiply(G).Mod(p);

            return new EdDSAPoint25517(X3, Y3, Z3, T3);
        }

        EdDSAPoint25517 Double()
        {
            BigInteger A = this.X.Square().Mod(p);
            BigInteger B = this.Y.Square().Mod(p);
            BigInteger C = this.Z.Square().Mod(p).Multiply(Two).Mod(p);
            BigInteger H = A.Add(B).Mod(p);
            BigInteger XpY = this.X.Add(this.Y).Mod(p).Square().Mod(p);
            BigInteger E = H.Subtract( XpY).Mod(p);

            BigInteger G = A.Subtract(B).Mod(p);
            BigInteger F = C.Add(G).Mod(p);

            return new EdDSAPoint25517(E.Multiply(F).Mod(p), G.Multiply(H).Mod(p), F.Multiply(G).Mod(p), E.Multiply(H).Mod(p));
        }

        public override EdDSAPoint MultipleByScalar(BigInteger k)
        {
            int i;
            EdDSAPoint25517 result = new EdDSAPoint25517(zero, one, one, zero);
            EdDSAPoint25517 pNext = this;

            for (i = 0; i < k.BitLength; i++) {
                if (k.TestBit(i)) {
                    result = Add(pNext, result);
                }
                pNext = pNext.Double();
            }

            return result.Normalize();
        }

        override public EdDSAPoint Normalize()
        {
            if (Z.Equals(one)) return this;

            BigInteger zInv = Z.ModInverse(p);
            BigInteger x = X.Multiply(zInv).Mod(p);
            BigInteger y = Y.Multiply(zInv).Mod(p);
            return new EdDSAPoint25517(x, y, p);
        }

        override public byte[] Encode()
        {
            EdDSAPoint25517 point = (EdDSAPoint25517) this.Normalize();

            byte[] rgbY = new byte[32];
            Array.Copy(point.Y.ToByteArrayUnsigned(), rgbY, rgbY.Length);
            rgbY[0] |= (byte) (point.X.TestBit(0) ? 0x80 : 0);
            Array.Reverse(rgbY);

            return rgbY;
        }

    }

    public class EdDSAPoint448 : EdDSAPoint
    {        
        public readonly static BigInteger p = Two.Pow(448).Subtract(Two.Pow(224)).Subtract(one);
        public readonly static EdDSAPoint448 B = new EdDSAPoint448(
            new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"),
            new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));   
            

        public readonly static BigInteger d = new BigInteger("-39081").Mod(p);
        
    public readonly static BigInteger L = Two.Pow(446).Subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

#if false
        readonly static BigInteger p = new BigInteger("2").Pow(255).Subtract(new BigInteger("19"));
        readonly static BigInteger d = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");

#endif 
        public EdDSAPoint448(BigInteger xIn, BigInteger yIn)
        {
            X = xIn;
            Y = yIn;
            Z = one;
        }

        public EdDSAPoint448(BigInteger xIn, BigInteger yIn, BigInteger zIn)
        {
            X = xIn;
            Y = yIn;
            Z = zIn;
        }

        static public EdDSAPoint448 Add(EdDSAPoint448 p1, EdDSAPoint448 p2)
        {
            BigInteger A = p1.Z.Multiply(p2.Z).Mod(p);
            BigInteger B = A.Square().Mod(p);
            BigInteger C = p1.X.Multiply(p2.X).Mod(p);
            BigInteger D = p1.Y.Multiply(p2.Y).Mod(p);
            BigInteger E = d.Multiply(C).Mod(p).Multiply(D).Mod(p);
            BigInteger F = B.Subtract(E).Mod(p);
            BigInteger G = B.Add(E).Mod(p);
            BigInteger H = (p1.X.Add(p1.Y)).Mod(p).Multiply(p2.X.Add(p2.Y).Mod(p)).Mod(p);
            BigInteger X3 = A.Multiply(F).Mod(p).Multiply(H.Subtract(C).Mod(p).Subtract(D).Mod(p)).Mod(p);
            BigInteger Y3 = A.Multiply(G).Mod(p).Multiply(D.Subtract(C).Mod(p)).Mod(p);
            BigInteger Z3 = F.Multiply(G).Mod(p);

            return new EdDSAPoint448(X3, Y3, Z3);
        }

        EdDSAPoint448 Double()
        {
            EdDSAPoint tmp = new EdDSAPoint448(zero, one);
            BigInteger C = this.X.Square().Mod(p);
            BigInteger D = this.Y.Square().Mod(p);
            BigInteger H = this.Z.Square().Mod(p);

            BigInteger E = C.Add(D).Mod(p);
            BigInteger B = this.X.Add(this.Y).Mod(p).Square().Mod(p);
            BigInteger J = E.Subtract(H.Add(H).Mod(p)).Mod(p);

            BigInteger X = B.Subtract(E).Mod(p).Multiply(J).Mod(p);
            BigInteger Y = E.Multiply(C.Subtract(D).Mod(p)).Mod(p);
            BigInteger Z = E.Multiply(J).Mod(p);

            return new EdDSAPoint448(X, Y, Z);

//                return Add(this, this);
        }

        public override EdDSAPoint MultipleByScalar(BigInteger k)
        {
            int i;
            EdDSAPoint448 result = new EdDSAPoint448(zero, one, one);
            EdDSAPoint448 pNext = this;

            for (i = 0; i < k.BitLength; i++) {
                if (k.TestBit(i)) {
                    result = Add(pNext, result);
                }
                pNext = pNext.Double();
            }

            return result.Normalize();
        }

        override public EdDSAPoint Normalize()
        {
            if (Z.Equals(one)) return this;

            BigInteger zInv = Z.ModInverse(p);
            BigInteger x = X.Multiply(zInv).Mod(p);
            BigInteger y = Y.Multiply(zInv).Mod(p);
            return new EdDSAPoint448(x, y);
        }

        override public byte[] Encode()
        {
            EdDSAPoint point = this.Normalize();

            byte[] rgbY = new byte[57];
            byte[] y = point.Y.ToByteArrayUnsigned();
            Array.Copy(y, 0, rgbY, 57-y.Length, y.Length);
            rgbY[0] |= (byte) (point.X.TestBit(0) ? 0x80 : 0);
            Array.Reverse(rgbY);

            return rgbY;
        }
    }

    public abstract class EdDSA
    {
        public abstract EdDSAPoint DecodePoint(byte[] key);
        public abstract EdDSAPoint GetPublic(byte[] privateKey);
        public byte[] Sign(EdDSAPoint publicPoint, byte[] privateKey, byte[] M, byte[] rgbContext=null)
        {
            return Sign(publicPoint.Encode(), privateKey, M, rgbContext);
        }
        public abstract byte[] Sign(byte[] publicKey, byte[] privateKey, byte[] M, byte[] rgbContext=null);
        public abstract Boolean Verify(byte[] publicKey, byte[] message, byte[] signature, byte[] rgbContext = null);
        public abstract byte[] Dom(byte[] rgbContext);
        public virtual byte[] PreHash(byte[] rgb) { return rgb; }
    }

    public class EdDSA25517 : EdDSA
    {
        readonly static BigInteger p = new BigInteger("2").Pow(255).Subtract(new BigInteger("19"));
        readonly static BigInteger zero = new BigInteger("0");
        readonly static BigInteger One = new BigInteger("1");
        readonly static BigInteger Two = new BigInteger("2");

        readonly static BigInteger d = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");
        readonly static BigInteger p_m5 = p.Subtract(new BigInteger("5")).Divide(new BigInteger("8"));
        readonly static BigInteger p_m1 = p.Subtract(One).Divide(new BigInteger("4"));

        readonly static BigInteger L = new BigInteger("2").Pow(252).Add(new BigInteger("27742317777372353535851937790883648493"));

        public override EdDSAPoint DecodePoint(byte[] key)
        {
            byte[] tmp = new byte[key.Length];
            Array.Copy(key, tmp, key.Length);
            Array.Reverse(tmp);
            bool x_0 = (tmp[0] & 0x80) != 0;
            tmp[0] &= (byte) 0x7f;
            BigInteger y = new BigInteger(1, tmp);

            if (y.CompareTo(p) > 0) throw new CoseException("Invalid point");

            BigInteger y2 = y.Multiply(y).Mod(p);
            BigInteger u = y2.Subtract(One).Mod(p);
            BigInteger v = d.Multiply(y2).Add(One).Mod(p);

#if false
            BigInteger u = y.Square().Subtract(One).Mod(p);
            BigInteger v = d.Multiply(y.Square().Mod(p)).Add(One).Mod(p);
            BigInteger x;

            BigInteger qq = u.Multiply(v.Pow(7).Mod(p)).ModPow(p_m5, p);
            x = u.Multiply(v.Pow(3).Mod(p)).Multiply(qq).Mod(p);
#else
            BigInteger vInv = v.ModPow(p.Subtract(Two), p);
            BigInteger uDivV = u.Multiply(vInv).Mod(p);
            BigInteger power = p.Add(new BigInteger("3")).Divide(new BigInteger("8"));
            BigInteger x = uDivV.ModPow(power, p);
            BigInteger qq;
#endif

            qq = x.Square().Mod(p).Multiply(v).Mod(p);
            if (qq.Equals(u)) {
                ;
            }
            else if (qq.Equals(u.Negate().Mod(p))) {
                x = x.Multiply(Two.ModPow(p_m1, p)).Mod(p);
            }
            else throw new CoseException("Invalid point");

            if (x_0 && x.Equals(zero)) throw new CoseException("Invalid point");
            if (x_0 != x.Mod(Two).Equals(One)) x = p.Subtract(x).Mod(p);

            return new EdDSAPoint25517(x, y, p);
        }


        public override EdDSAPoint GetPublic(byte[] privateKey)
        {
            Sha512Digest sha512 = new Sha512Digest();
            byte[] h = new byte[64];
            sha512.BlockUpdate(privateKey, 0, 32);
            sha512.DoFinal(h, 0);
            Array.Resize(ref h, 32);
            h[0] &= 0xf8; // Clear lowest 3 bits
            h[31] |= 0x40; // Set the highest bit
            h[31] &= 0x7f; // Clear the highest bit
            Array.Reverse(h);
            BigInteger a = new BigInteger(1, h);
            EdDSAPoint25517 publicKey = (EdDSAPoint25517) EdDSAPoint25517.B.MultipleByScalar(a);

            return publicKey;
        }

        public override byte[] Sign(byte[] publicKey, byte[] privateKey, byte[] M, byte[] rgbContext=null)
        { 
            Sha512Digest sha512 = new Sha512Digest();
            sha512.BlockUpdate(privateKey, 0, privateKey.Length);
            byte[] h = new byte[sha512.GetDigestSize()];
            sha512.DoFinal(h, 0);
            byte[] x = new byte[32];
            Array.Copy(h, x, 32);
            x[0] &= 0xf8; // Clear lowest 3 bits
            x[31] |= 0x40; // Set the highest bit
            x[31] &= 0x7f; // Clear the highest bit
            Array.Reverse(x);
            byte[] prefix = new byte[32];
            Array.Copy(h, 32, prefix, 0, 32);
            BigInteger a = new BigInteger(1, x);
            byte[] A = publicKey;

            M = PreHash(M);

            sha512.Reset();
            byte[] dom = Dom(rgbContext);
            sha512.BlockUpdate(dom, 0, dom.Length);
            sha512.BlockUpdate(prefix, 0, prefix.Length);
            sha512.BlockUpdate(M, 0, M.Length);
            byte[] r1 = new byte[64];
            sha512.DoFinal(r1, 0);
            Array.Reverse(r1);
            BigInteger r = new BigInteger(1, r1).Mod(L);
            EdDSAPoint25517 rB = (EdDSAPoint25517) EdDSAPoint25517.B.MultipleByScalar(r);
            byte[] R = rB.Encode();

            sha512.Reset();
            sha512.BlockUpdate(dom, 0, dom.Length);
            sha512.BlockUpdate(R, 0, R.Length);
            sha512.BlockUpdate(A, 0, A.Length);
            sha512.BlockUpdate(M, 0, M.Length);
            byte[] kBytes = new byte[64];
            sha512.DoFinal(kBytes, 0);
            Array.Reverse(kBytes);
            BigInteger k = new BigInteger(1, kBytes).Mod(L);
            BigInteger S = r.Add(k.Multiply(a)).Mod(L);

            byte[] hash = new byte[64];
            byte[] s = S.ToByteArrayUnsigned();
            Array.Copy(s, 0, hash, 32-s.Length, s.Length);
            Array.Reverse(hash);
            Array.Copy(R, hash, 32);

            return hash;
        }

        public override Boolean Verify(byte[] publicKey, byte[] message, byte[] signature, byte[] rgbContext = null)
        {
            EdDSAPoint A = DecodePoint(publicKey);
            byte[] r = new byte[signature.Length / 2];
            Array.Copy(signature, r, r.Length);
            EdDSAPoint R = DecodePoint(r);
            byte[] s = new byte[signature.Length / 2];
            Array.Copy(signature, r.Length, s, 0, r.Length);
            Array.Reverse(s);
            BigInteger S = new BigInteger(1, s);

            message = PreHash(message);

            Sha512Digest sha256 = new Sha512Digest();
            byte[] dom = Dom(rgbContext);
            sha256.BlockUpdate(dom, 0, dom.Length);
            sha256.BlockUpdate(r, 0, r.Length);
            sha256.BlockUpdate(publicKey, 0, publicKey.Length);
            sha256.BlockUpdate(message, 0, message.Length);
            byte[] h = new byte[64];
            sha256.DoFinal(h, 0);
            Array.Reverse(h);
            BigInteger k = new BigInteger(1, h).Mod(L);

            EdDSAPoint left = EdDSAPoint25517.B.MultipleByScalar(S).Normalize();
            EdDSAPoint right = EdDSAPoint25517.Add((EdDSAPoint25517) R, (EdDSAPoint25517) A.MultipleByScalar(k)).Normalize();

            return left.equal(right);
        }

        public override byte[] Dom(byte[] rgbContext)
        {
            if (rgbContext != null) throw new Exception("Context MUST be empty");
            return new byte[0];
        }


        static public void SelfTest()
        {
            BigInteger privateKey = new BigInteger("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", 16);
            byte[] message0 = new byte[0];
            EdDSA25517 x = new EdDSA25517();

            EdDSAPoint publicKey = x.GetPublic(privateKey.ToByteArrayUnsigned());
            publicKey = (EdDSAPoint25517) publicKey.Normalize();
            byte[] rgbPublicKey = publicKey.Encode();
            EdDSAPoint pt2 = x.DecodePoint(rgbPublicKey);


            byte[] signature = x.Sign(rgbPublicKey, privateKey.ToByteArrayUnsigned(), message0);

            x.Verify(rgbPublicKey, message0, signature);
        }
    }

    public class EdDSA25517cxt : EdDSA25517
    {
        static byte[] domValue = new byte[] { 0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0, 0 };
        public override byte[] Dom(byte[] rgbContext)
        {
            byte[] x = new byte[34 + rgbContext.Length];
            Array.Copy(domValue, x, domValue.Length);
            if (rgbContext.Length > 255) throw new Exception("context must be less than 256 bytes");
            x[33] = (byte) rgbContext.Length;
            Array.Copy(rgbContext, 0, x, domValue.Length, rgbContext.Length);
            return x;
        }
    }

    public class EdDSA25517ph : EdDSA25517
    {
        static byte[] domValue = new byte[] { 0x53, 0x69, 0x67, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x6e, 0x6f, 0x20, 0x45, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39, 0x20, 0x63, 0x6f, 0x6c, 0x6c, 0x69, 0x73, 0x69, 0x6f, 0x6e, 0x73, 1, 0 };
        public override byte[] Dom(byte[] rgbContext)
        {
            if (rgbContext == null) rgbContext = new byte[0];

            byte[] x = new byte[34 + rgbContext.Length];
            Array.Copy(domValue, x, domValue.Length);
            if (rgbContext.Length > 255) throw new Exception("context must be less than 256 bytes");
            x[33] = (byte) rgbContext.Length;
            Array.Copy(rgbContext, 0, x, domValue.Length, rgbContext.Length);
            return x;
        }

        public override byte[] PreHash(byte[] rgb)
        {
            Sha512Digest digest = new Sha512Digest();
            digest.BlockUpdate(rgb, 0, rgb.Length);
            byte[] result = new byte[64];
            digest.DoFinal(result, 0);
            return result;
        }
    }

    public class EdDSA448 : EdDSA
    {

        public override EdDSAPoint DecodePoint(byte[] key)
        {
            byte[] tmp = new byte[key.Length];
            Array.Copy(key, tmp, key.Length);
            Array.Reverse(tmp);
            bool x_0 = tmp[0] != 0;
            BigInteger y = new BigInteger(1, tmp, 1, tmp.Length-1);

            if (y.CompareTo(EdDSAPoint448.p) > 0) throw new CoseException("Invalid point");

            BigInteger y2 = y.Multiply(y).Mod(EdDSAPoint448.p);
            BigInteger u = y2.Subtract(EdDSAPoint448.one).Mod(EdDSAPoint448.p);
            BigInteger v = EdDSAPoint448.d.Multiply(y2).Subtract(EdDSAPoint448.one).Mod(EdDSAPoint448.p);

#if false
            BigInteger u = y.Square().Subtract(One).Mod(p);
            BigInteger v = d.Multiply(y.Square().Mod(p)).Add(One).Mod(p);
            BigInteger x;

            BigInteger qq = u.Multiply(v.Pow(7).Mod(p)).ModPow(p_m5, p);
            x = u.Multiply(v.Pow(3).Mod(p)).Multiply(qq).Mod(p);
#else
            BigInteger vInv = v.ModPow(EdDSAPoint448.p.Subtract(EdDSAPoint448.Two), EdDSAPoint448.p);
            BigInteger uDivV = u.Multiply(vInv).Mod(EdDSAPoint448.p);
            BigInteger power = EdDSAPoint448.p.Add(new BigInteger("1")).Divide(new BigInteger("4"));
            BigInteger x = uDivV.ModPow(power, EdDSAPoint448.p);
            BigInteger qq;
#endif

            qq = x.Square().Mod(EdDSAPoint448.p).Multiply(v).Mod(EdDSAPoint448.p);
            if (qq.Equals(u)) {
                ;
            }
            else throw new CoseException("Invalid point");

            if (x_0 && x.Equals(EdDSAPoint448.zero)) throw new CoseException("Invalid point");
            if (x_0 != x.Mod(EdDSAPoint448.Two).Equals(EdDSAPoint448.one)) x = EdDSAPoint448.p.Subtract(x).Mod(EdDSAPoint448.p);

            return new EdDSAPoint448(x, y);
        }


        public override EdDSAPoint GetPublic(byte[] privateKey)
        {
            if (privateKey.Length != 57) throw new CoseException("Invalid private key");

            ShakeDigest shake = new ShakeDigest(256);
            byte[] h = new byte[114];
            shake.BlockUpdate(privateKey, 0, privateKey.Length);
            shake.DoFinal(h, 0, 114);

            Array.Resize(ref h, 57);

            h[0] &= 0xfc; // Clear lowest 2 bits
            h[56] = 0; // Clear the highest byte
            h[55] |= 0x80; // Set the highest bit
            Array.Reverse(h);
            BigInteger a = new BigInteger(1, h);
            EdDSAPoint448 publicKey = (EdDSAPoint448) EdDSAPoint448.B.MultipleByScalar(a);

            return publicKey;
        }

        static readonly byte[] rgbAlg = new byte[] { (byte) 'S', (byte) 'i', (byte) 'g', (byte) 'E', (byte) 'd', (byte) '4', (byte) '4', (byte) '8', 0, 0 };
        public override byte[] Dom(byte[] rgbContext)
        {
            if (rgbContext == null) rgbContext = new byte[0];
            byte[] x = new byte[rgbAlg.Length + rgbContext.Length];
            if (rgbContext.Length > 255) throw new Exception("Context must be less than 256 bytes");
            Array.Copy(rgbAlg, x, rgbAlg.Length);
            x[rgbAlg.Length - 1] = (byte) rgbContext.Length;
            Array.Copy(rgbContext, 0, x, rgbAlg.Length, rgbContext.Length);
            return x;
        }

        public override byte[] Sign(byte[] publicKey, byte[] privateKey, byte[] M, byte[] context = null)
        {
            ShakeDigest sha512 = new ShakeDigest(256);
            sha512.BlockUpdate(privateKey, 0, privateKey.Length);
            byte[] h = new byte[114];
            sha512.DoFinal(h, 0, 114);
            byte[] x = new byte[57];
            Array.Copy(h, x, 57);
            x[0] &= 0xfc; // Clear lowest 2 bits
            x[56] = 0; // Clear the highest byte
            x[55] |= 0x80; // Set the highest bit
            Array.Reverse(x);
            BigInteger a = new BigInteger(1, x);
            byte[] A = publicKey;

            byte[] prefix = new byte[57];
            Array.Copy(h, 57, prefix, 0, 57);

            M = PreHash(M);

            sha512.Reset();
            byte[] domBytes = Dom(context);
            sha512.BlockUpdate(domBytes, 0, domBytes.Length);
            sha512.BlockUpdate(prefix, 0, prefix.Length);
            sha512.BlockUpdate(M, 0, M.Length);
            byte[] r1 = new byte[114];
            sha512.DoFinal(r1, 0, 114);
            Array.Reverse(r1);
            BigInteger r = new BigInteger(1, r1).Mod(EdDSAPoint448.L);
            EdDSAPoint rB = EdDSAPoint448.B.MultipleByScalar(r);
            byte[] R = rB.Encode();

            sha512.Reset();
            sha512.BlockUpdate(domBytes, 0, domBytes.Length);
            sha512.BlockUpdate(R, 0, R.Length);
            sha512.BlockUpdate(A, 0, A.Length);
            sha512.BlockUpdate(M, 0, M.Length);
            byte[] kBytes = new byte[114];
            sha512.DoFinal(kBytes, 0, 114);
            Array.Reverse(kBytes);
            BigInteger k = new BigInteger(1, kBytes).Mod(EdDSAPoint448.L);
            BigInteger S = r.Add(k.Multiply(a)).Mod(EdDSAPoint448.L);

            byte[] hash = new byte[57*2];
            byte[] rgbS = S.ToByteArrayUnsigned();
            Array.Copy(rgbS, 0, hash, 57-rgbS.Length, rgbS.Length);
            Array.Reverse(hash);
            Array.Copy(R, hash, 57);

            return hash;
        }

        public override Boolean Verify(byte[] publicKey, byte[] message, byte[] signature, byte[] rgbContext= null)
        {
            EdDSAPoint A = DecodePoint(publicKey);
            byte[] r = new byte[signature.Length / 2];
            Array.Copy(signature, r, r.Length);
            EdDSAPoint R = DecodePoint(r);
            byte[] s = new byte[signature.Length / 2];
            Array.Copy(signature, r.Length, s, 0, r.Length);
            Array.Reverse(s);
            BigInteger S = new BigInteger(1, s);

            message = PreHash(message);

            ShakeDigest sha256 = new ShakeDigest(256);
            byte[] rgbDom = Dom(rgbContext);
            sha256.BlockUpdate(rgbDom, 0, rgbDom.Length);
            sha256.BlockUpdate(r, 0, r.Length);
            sha256.BlockUpdate(publicKey, 0, publicKey.Length);
            sha256.BlockUpdate(message, 0, message.Length);
            byte[] h = new byte[114];
            sha256.DoFinal(h, 0, 114);
            Array.Reverse(h);
            BigInteger k = new BigInteger(1, h).Mod(EdDSAPoint448.L);

            EdDSAPoint left = EdDSAPoint448.B.MultipleByScalar(S).Normalize();
            EdDSAPoint right = EdDSAPoint448.Add((EdDSAPoint448) R, (EdDSAPoint448) A.MultipleByScalar(k)).Normalize();

            return left.equal(right);
        }
        public static void SelfTest()
        {
            BigInteger secretkey = new BigInteger("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b", 16);
            BigInteger publicKey = new BigInteger("b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80", 16);

            //byte[] rgbMessage = new byte[] { 0x64, 0xa6, 0x5f, 0x3c, 0xde, 0xdc, 0xdd, 0x66, 0x81, 0x1e, 0x29, 0x15, 0xe7 };
            byte[] rgbMessage = new byte[0];
            EdDSA448 x = new EdDSA448();

            BigInteger signature = new BigInteger("6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100", 16);

            EdDSAPoint publicPoint = x.GetPublic(secretkey.ToByteArrayUnsigned());
            byte[] rgbPublic = publicPoint.Normalize().Encode();

            byte[] rgbSig = x.Sign(rgbPublic, secretkey.ToByteArrayUnsigned(), rgbMessage);

            EdDSAPoint decodePoint = x.DecodePoint(rgbPublic);

            x.Verify(rgbPublic, rgbMessage, rgbSig);
            
        }

    }
    public class EdDSA448ph : EdDSA448  {
        public override byte[] PreHash(byte[] Message)
        {
            ShakeDigest digest = new ShakeDigest(256);
            digest.BlockUpdate(Message, 0, Message.Length);
            byte[] result = new byte[64];
            digest.DoFinal(result, 0, 64);
            return result;
        }

        static readonly byte[] rgbAlg = new byte[] { (byte) 'S', (byte) 'i', (byte) 'g', (byte) 'E', (byte) 'd', (byte) '4', (byte) '4', (byte) '8', 1, 0 };
        public override byte[] Dom(byte[] rgbContext)
        {
            if (rgbContext == null) rgbContext = new byte[0];
            byte[] x = new byte[rgbAlg.Length + rgbContext.Length];
            if (rgbContext.Length > 255) throw new Exception("Context must be less than 256 bytes");
            Array.Copy(rgbAlg, x, rgbAlg.Length);
            x[rgbAlg.Length - 1] = (byte) rgbContext.Length;
            Array.Copy(rgbContext, 0, x, rgbAlg.Length, rgbContext.Length);
            return x;
        }

    }
}
