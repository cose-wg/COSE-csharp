using System;
using System.Linq;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;

namespace Com.AugustCellars.COSE
{
    public class HashSig
    {
        class Constants
        {
            public int w;
            public int p;
            public int ls;
            public int Height;

            public Constants(int nIn, int wIn, int pIn, int lsIn)
            {
                HashLength = nIn;
                w = wIn;
                p = pIn;
                ls = lsIn;
            }

            public Constants(int mIn, int hIn)
            {
                HashLength = mIn;
                Height = hIn;
            }

            static public Constants[] Values = new Constants[] {
                null,
                new Constants(32, 1, 256, 7), // LMOTS_SHA256_N32_W1 (1)
                new Constants(32, 2, 133, 6), // LMOTS_SHA256_N32_W2 (2)
                new Constants(32, 4, 67, 4),  // LMOTS_SHA256_N32_W4 (3)
                new Constants(32, 8, 34, 0),  // LMOTS_SHA256_N32_W8 (4)
                new Constants(32, 5),  // LMS_SHA256_M32_H5 (5)
                new Constants(32, 10), // LMS_SHA256_M32_H10 (6)
                new Constants(32, 15), // LMS_SHA256_M32_H15 (7)
                new Constants(32, 20), // LMS_SHA256_M32_H20 (8)
                new Constants(32, 25), // LMS_SHA256_M32_H25 (9)
            };

            public int HashLength { get; }
        }

        class LmsKey
        {
            private readonly LmsAlgorithmType _lmsType;
            private readonly LmotsAlgorithmType _lmotsType;
            private byte[] Identifier;
            private byte[][] _x;
            public int LeafNumber { get; private set; }
            private readonly byte[] _seed;

            public LmsKey(LmsAlgorithmType lmsTypeIn, LmotsAlgorithmType lmotsTypeIn)
            {
                _lmsType = lmsTypeIn;
                _lmotsType = lmotsTypeIn;
                Identifier = new byte[16];

                SecureRandom rng = Message.GetPRNG();
                rng.NextBytes(Identifier, 0, 16);

                _seed = new byte[M];
                rng.NextBytes(_seed, 0, _seed.Length);
BuildFromSeed(_seed);
            }

            /// <summary>
            /// Take an array of strings and fill in the private key from that
            /// Fields in order are:  LMS type, LMOTS type, Seed, Q, Identifier
            /// </summary>
            /// <param name="input"></param>
            /// <param name="offset"></param>
            public LmsKey(string[] input, int offset)
            {
                _lmsType = (LmsAlgorithmType) Int32.Parse(input[offset]);
                _lmotsType = (LmotsAlgorithmType) Int32.Parse(input[offset + 1]);
                _seed = StringToByteArray(input[offset + 2]);
                LeafNumber = Int32.Parse(input[offset + 3]);
                Identifier = StringToByteArray(input[offset + 4]);

                BuildFromSeed(_seed);
            }

            private void BuildFromSeed(byte[] seed)
            {
                if (seed.Length != M) {
                    throw new CoseException("Incorrect seed length");
                }

                int keyCount = 1 << H;
                int p = Constants.Values[(int) _lmotsType].p;

                _x = new byte[keyCount][];
                //  Build LMS Private Key
                for (int q = 0; q < keyCount; q++) {
                    byte[] qBytes = u32str(q);
                    //  Build LM-OTS private key for each leaf
                    _x[q] = new byte[M*p];
                    for (UInt16 j = 0; j < p; j++) {
                        Sha256Digest h = new Sha256Digest();
                        h.BlockUpdate(Identifier, 0, Identifier.Length);
                        h.BlockUpdate(qBytes, 0, qBytes.Length);
                        h.BlockUpdate(u16str(j), 0, 2);
                        h.Update(0xff);
                        h.BlockUpdate(seed, 0, seed.Length);
                        h.DoFinal(_x[q], j*M);
                    }
                }

                // Derive the public key

                ComputePublicKey();
            }

            private int M
            {
                get {
                    switch (_lmsType) {
                        case LmsAlgorithmType.Sha256_m32_h5:
                        case LmsAlgorithmType.Sha256_m32_h10:
                        case LmsAlgorithmType.Sha256_m32_h15:
                        case LmsAlgorithmType.Sha256_m32_h20:
                        case LmsAlgorithmType.Sha256_m32_h25:
                            return 32;

                        default:
                            throw new CoseException($"Unknown LmsAlgorithmType value {_lmsType}");
                    }
                }
            }

            private int H {
                get {
                    switch (_lmsType) {
                    case LmsAlgorithmType.Sha256_m32_h5:
                        return 5;

                    case LmsAlgorithmType.Sha256_m32_h10:
                        return 10;

                    case LmsAlgorithmType.Sha256_m32_h15:
                        return 15;

                    case LmsAlgorithmType.Sha256_m32_h20:
                        return 20;

                    case LmsAlgorithmType.Sha256_m32_h25:
                        return 25;

                    default:
                        throw new CoseException($"Unknown LmsAlgorithmType value {_lmsType}");
                    }
                }
            }

            public void GetPublicKey(StringBuilder sb)
            {
                sb.Append($"{_lmsType}|{_lmotsType}|{GetHex(_seed)}|{LeafNumber}|{GetHex(Identifier)}");
            }

            private static string GetHex(byte[] value)
            {
                char[] x = new char[value.Length*2];
                for (int j = 0; j < value.Length; j++) {
                    x[j * 2] = hex[value[j] >> 4];
                    x[j * 2 + 1] = hex[value[j] & 0xf];
                }

                return x.ToString();
            }


            private byte[] _publicKey;

            public byte[] PublicKey
            {
                get {
                    if (_publicKey == null) {
                        ComputePublicKey();
                    }

                    return _publicKey;
                }
            }

            static byte[] D_INTR = new byte[]{0x83, 0x83};
            static byte[] D_LEAF = new byte[]{0x82, 0x82};
            private static byte[] D_PBLC = new byte[] {0x80, 0x80};

            private byte[] ComputePubPart(int i, int two2H)
            {
                Sha256Digest digest = new Sha256Digest();
                digest.BlockUpdate(Identifier, 0, Identifier.Length);
                digest.BlockUpdate(u32str(i), 0, 4);
                if (i >= two2H) {
                    digest.BlockUpdate(D_LEAF, 0, 2);
                    digest.BlockUpdate(LmtosPublic(i-two2H), 24, 32);
                }
                else {
                    digest.BlockUpdate(D_INTR, 0, 2);
                    digest.BlockUpdate(ComputePubPart(i * 2, two2H), 0, 32);
                    digest.BlockUpdate(ComputePubPart(i * 2 + 1, two2H), 0, 32);
                }

                byte[] result = new byte[32];
                digest.DoFinal(result, 0);
                return result;
            }

            private void ComputePublicKey()
            {
                byte[] key = new byte[8 + Identifier.Length + M];
                Array.Copy(u32str((Int32) _lmsType), key, 4);
                Array.Copy(u32str((Int32) _lmotsType), 0, key, 4, 4);
                Array.Copy(Identifier, 0, key, 8, Identifier.Length);
                Array.Copy(ComputePubPart(1, (int) Math.Pow(2, H)), 0, key, 8+Identifier.Length, 32);

                _publicKey = key;
            }

            private int BuildSigningPath(int leafNumber, byte[] signature, int offset, int depth)
            {
                int offsetNew;

                if (depth == H - 1) {
                    offsetNew = offset;
                }
                else {
                    offsetNew = BuildSigningPath(leafNumber, signature, offset, depth + 1);
                }

                int i = (1 << (depth+1)) + (leafNumber >> (H-1 - depth)) ^ 1;
                Array.Copy(ComputePubPart(i, (int) Math.Pow(2, H)), 0, signature, offsetNew, 32);
                return offsetNew + 32;
            }

            private byte[] LmtosPublic(int node)
            {
                int p = Constants.Values[(int) _lmotsType].p;
                int limit = (1 << Constants.Values[(int) _lmotsType].w) - 1;
                ushort i;
                byte[] q = u32str(node);
                byte[] jX = new byte[1];
                byte[][] y = new byte[p][];
                for (i = 0; i < p; i++) {
                    byte[] tmp = new byte[32];
                    Array.Copy(_x[node], i*32, tmp, 0, 32);
                    byte[] iX = u16str(i);
                    for (int j = 0; j < limit; j++) {
                        jX[0] = (byte) j;
                        tmp = ComputeHash(new Sha256Digest(), new byte[][]{Identifier, q, iX, jX, tmp});
                    }

                    y[i] = tmp;
                }

                IDigest dig = new Sha256Digest();
                dig.BlockUpdate(Identifier, 0, Identifier.Length);
                dig.BlockUpdate(q, 0, q.Length);
                dig.BlockUpdate(D_PBLC, 0, 2);
                for (i = 0; i < p; i++) {
                    dig.BlockUpdate(y[i], 0, y[i].Length);
                }

                byte[] K = new byte[32];
                dig.DoFinal(K, 0);

                byte[] pubKey = new byte[4 + 16 + 4 + K.Length];
                Array.Copy(u32str((int) _lmotsType), pubKey, 4);
                Array.Copy(Identifier, 0, pubKey, 4, Identifier.Length);
                Array.Copy(q, 0, pubKey, 20, 4);
                Array.Copy(K, 0, pubKey, 24, K.Length);

                return pubKey;
            }

            private static byte[] ComputeHash(IDigest digest, byte[][] dataToHash)
            {
                foreach (byte[] rgb in dataToHash) {
                    digest.BlockUpdate(rgb, 0, rgb.Length);
                }
                byte[] output = new byte[digest.GetDigestSize()];
                digest.DoFinal(output, 0);
                return output;
            }

            public byte[] Sign(byte[] message)
            {
                if (LeafNumber == (1 << H)) {

                }

                byte[] lmotsSignature = SignOnce(message);

                byte[] signature = new byte[4 + lmotsSignature.Length + 4 + H * M];

                Array.Copy(u32str(LeafNumber), signature, 4);
                Array.Copy(lmotsSignature, 0, signature, 4, lmotsSignature.Length);
                Array.Copy(u32str((Int32) _lmsType), 0, signature, 4 + lmotsSignature.Length, 4);
                BuildSigningPath(LeafNumber, signature, 8 + lmotsSignature.Length, 0);
                LeafNumber += 1;
                return signature;
            }

            public static bool Validate(byte[] message, byte[] key, byte[] signature)
            {
                if (key.Length < 8) return false;
                UInt32 pubType = strTou32(key, 0);
                UInt32 ost_typecode = strTou32(key, 4);
                int hashLength = Constants.Values[pubType].HashLength;
                if (key.Length != 24 + hashLength) {
                    return false;
                }

                byte[] identifier = new byte[16];
                Array.Copy(key, 8, identifier, 0, 16);
                byte[] T1 = new byte[hashLength];
                Array.Copy(key, 24, T1, 0, hashLength);

                //  Compute LMS Public Key Candiate
                if (signature.Length < 8) {
                    return false;
                }

                UInt32 q = strTou32(signature, 0);
                UInt32 otssigtype = strTou32(signature, 4);
                if (otssigtype != ost_typecode) {
                    return false;
                }

                int n = Constants.Values[otssigtype].HashLength;
                int p = Constants.Values[otssigtype].p;

                if (signature.Length < 12 + n * (p + 1)) {
                    return false;
                }

                byte[] lmots_signature = new byte[4+n*(p+1)];
                Array.Copy(signature, 4, lmots_signature, 0, lmots_signature.Length);
                UInt32 sigtype = strTou32(signature, 8 + n * (p + 1));
                if (sigtype != pubType) {
                    return false;
                }

                hashLength = Constants.Values[sigtype].HashLength;
                int h = Constants.Values[sigtype].Height;

                if ((q >= (UInt32)(1 << h)) || (signature.Length != (12 + n * (p + 1) + hashLength * h))) {
                    return false;
                }

                byte[] Kc = ValidateOnce(key, message, lmots_signature, u32str(q));

                int node_num = ((int) q) +  (1 << h);
                byte[] tmp = ComputeHash(new Sha256Digest(), new byte[][] {identifier, u32str(node_num), D_LEAF, Kc});
                int i = 0;
                byte[] path = new byte[hashLength];
                int offsetPath = 12 + n * (p + 1);
                while (node_num > 1) {
                    Array.Copy(signature, offsetPath +  i*hashLength, path, 0, hashLength);
                    if ((node_num & 1) != 0) {
                        tmp = ComputeHash(new Sha256Digest(),
                                          new byte[][] {identifier, u32str(node_num / 2), D_INTR, path, tmp});
                    }
                    else {
                        tmp = ComputeHash(new Sha256Digest(),
                                          new byte[][] {identifier, u32str(node_num / 2), D_INTR, tmp, path});
                    }

                    node_num = node_num / 2;
                    i += 1;
                }

                return T1.SequenceEqual(tmp);
            }

            private static byte[] ValidateOnce(byte[] key, byte[] message, byte[] signature, byte[] q)
            {
                UInt32 pubtype = strTou32(key, 0);
                int n = Constants.Values[pubtype].HashLength;
                UInt32 otsType = strTou32(key, 4);
                byte[] identifier = new byte[16];
                byte[] k = new byte[n];
                Array.Copy(key, 8, identifier, 0, 16);
                Array.Copy(key, 8 + 16, k, 0, n);

                if (signature.Length < 4) {
                    return null;
                }

                UInt32 sigtype = strTou32(signature, 0);
                if (sigtype != otsType) {
                    return null;
                }

                n = Constants.Values[sigtype].HashLength;
                int p = Constants.Values[sigtype].p;
                int w = Constants.Values[sigtype].w;
                if (signature.Length != 4 + n + n * p) {
                    return null;
                }

                byte[] random = new byte[n];
                Array.Copy(signature, 4, random, 0, n);

                int nOffset = 4 + n;

                byte[] Q = ComputeHash(new Sha256Digest(),
                                       new byte[][] {identifier, q, D_MESG, random, message});
                byte[] QNew = new byte[Q.Length + 2];
                Array.Copy(Q, QNew, Q.Length);
                int limit = (1 <<  w) - 1;

                IDigest digest = new Sha256Digest();
                digest.BlockUpdate(identifier, 0, identifier.Length);
                digest.BlockUpdate(q, 0, q.Length);
                digest.BlockUpdate(D_PBLC, 0, D_PBLC.Length);


                byte[] tmp = new byte[n];
                for (int i = 0; i < p; i += 1) {
                    Array.Copy(u16str(Checksum(Q, w, (LmotsAlgorithmType) sigtype)), 0, QNew, Q.Length, 2);
                    int a = Coef(QNew, i, w);
                    Array.Copy(signature, nOffset, tmp, 0, n);
                    nOffset += n;
                    for (int j = a; j < limit; j++) {
                        tmp = ComputeHash(new Sha256Digest(), new byte[][] { identifier, q, u16str((UInt16)i), new byte[] { (byte)j }, tmp });
                    }
                    digest.BlockUpdate(tmp, 0, tmp.Length);

                }

                byte[] result = new byte[digest.GetDigestSize()];
                digest.DoFinal(result, 0);
                return result;
            }

            public static int PublicKeyLength(byte[] buffer, int offset)
            {
                // u32str(type) || u32str(otstype) || I || T[1]
                UInt32 type = strTou32(buffer, offset);
                int n = Constants.Values[type].HashLength;
                return 4 + 4 + 16 + n;
            }

            public static int SignatureLength(byte[] buffer, int offset)
            {
               //  u32str(q) || lmots_signature || u32str(type) ||
                //    path[0] || path[1] || path[2] || ... || path[h - 1]

                int cb = LmsotSignatureLength(buffer, offset + 4);
                UInt32 type = strTou32(buffer, offset+4+cb);
                int h = Constants.Values[type].HashLength;
                int m = Constants.Values[type].Height;

                return 8 + cb + h * m;
            }

            public static int LmsotSignatureLength(byte[] buffer, int offset)
            {
                UInt32 type = strTou32(buffer, offset);
                int n = Constants.Values[type].HashLength;
                int p = Constants.Values[type].p;

                return 4 + n + p * n;
            }

            private static byte[] D_MESG = new byte[]{0x81, 0x81};

            private static UInt16 Checksum(byte[] Q, int w, LmotsAlgorithmType lmotsType)
            {
                UInt16 sum = 0;
                UInt16 max = (UInt16) ((1 << w) - 1);
                for (int i = 0; i < (Q.Length * 8 / w); i += 1) {
                    sum += (UInt16) (max - Coef(Q, i, w));
                }

                return (UInt16) (sum << Constants.Values[(int) lmotsType].ls);
            }

            private static int Coef(byte[] Q, int i, int w)
            {
                int ret = ((1 << w) - 1) & (Q[i*w/8] >> (8 - (w * (i % (8 / w)) + w)));
                return ret;
            }

            private byte[] SignOnce(byte[] message)
            {
                Constants c = Constants.Values[(int) _lmotsType];
                int n =  c.HashLength;
                int p = c.p;
                int w = c.w;
                byte[] C = new byte[n];
                Message.GetPRNG().NextBytes(C);
                C = new byte[] {
                    0x91, 0x29, 0x1d, 0xe7,
                    0x6c, 0xe6, 0xe2, 0x4d, 0x1e, 0x2a, 0x9b, 0x60,
                    0x26, 0x65, 0x19, 0xbc, 0x8c, 0xe8, 0x89, 0xf8,
                    0x14, 0xde, 0xb0, 0xfc, 0x00, 0xed, 0xd3, 0x12,
                    0x9d, 0xe3, 0xab, 0x9b
                };

                byte[][] y = new byte[p][];
                byte[] Q = ComputeHash(new Sha256Digest(),
                                       new byte[][] {Identifier, u32str(LeafNumber), D_MESG, C, message});

                byte[] signature = new byte[4 + C.Length + p * M];
                Array.Copy(u32str((Int32) _lmotsType), 0, signature, 0, 4);
                Array.Copy(C, 0, signature, 4, C.Length);

                byte[] QNew = new byte[Q.Length + 2];
                Array.Copy(Q, QNew, Q.Length);
                byte[] privateKey = _x[LeafNumber];
                byte[] tmp = new byte[n];

                for (int i = 0; i < p; i++) {
                    Array.Copy(u16str(Checksum(Q, w, _lmotsType)), 0, QNew, Q.Length, 2);
                    int a = Coef(QNew, i, w);
                    Array.Copy(privateKey, i*n, tmp, 0, n);
                    for (int j = 0; j < a; j++) {
                        tmp = ComputeHash(new Sha256Digest(), new byte[][]{ Identifier, u32str(LeafNumber), u16str((UInt16) i), new byte[] {(byte) j}, tmp});
                    }

                    Array.Copy(tmp, 0, signature, 4 + C.Length + M * i, tmp.Length);
                }

                return signature;
            }

            private static byte[] u16str(UInt16 i)
            {
                byte[] bytes = BitConverter.GetBytes(i);
                if (BitConverter.IsLittleEndian) {
                    Array.Reverse(bytes);
                }

                return bytes;
            }

            public static string PrintSignature(byte[] signatureBytes, ref int offset)
            {
                UInt32 q = strTou32(signatureBytes, offset);
                offset += 4;

                string result = $"LMS signature\nq           {q}\n------------------------\n";

                result += PrintOneSignature(signatureBytes, ref offset);

                UInt32 lmsType = strTou32(signatureBytes, offset);
                Constants c = Constants.Values[lmsType];

                result += $"------------------------------\n";
                result += PrintBytes("LMS type", signatureBytes, ref offset, 4);
                for (int i = 0; i < c.Height; i++) {
                    result += PrintBytes($"path[{i}]", signatureBytes, ref offset, 32);
                }

                return result;
            }

            public static string PrintOneSignature(byte[] signatureBytes, ref int offset)
            {
                UInt32 lmotsType = strTou32(signatureBytes, offset);
                Constants c = Constants.Values[lmotsType];
                offset += 4;

                string result = $"LMOTS signature\nLMOTS type  {lmotsType}\n";
                result += PrintBytes("C", signatureBytes, ref offset, 32);

                for (int i = 0; i < c.p; i++) {
                    result += PrintBytes($"Y[{i}]", signatureBytes, ref offset, 32);
                }

                return result;
            }

            public static string PrintPublicKey(byte[] signatureBytes, ref int offset)
            {
                string result = "LMS public key\n";

                result += PrintBytes("LMS type", signatureBytes, ref offset, 4);
                result += PrintBytes("LMOTS type", signatureBytes, ref offset, 4);
                result += PrintBytes("I", signatureBytes, ref offset, 16);
                result += PrintBytes("K", signatureBytes, ref offset, 32);

                return result;
            }

            private static readonly char[] hex = new[] {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
            };

            private static string PrintBytes(string tag, byte[] signatureBytes, ref int offset, int count)
            {
                string result = "";
                char[] x = new char[32];
                for (int i = 0; i < count / 16; i++) {
                    for (int j = 0; j < 16; j++) {
                        x[j * 2] = hex[signatureBytes[offset] >> 4];
                        x[j * 2 + 1] = hex[signatureBytes[offset] & 0xf];
                        offset += 1;
                    }

                    if (i == 0) {
                        result += string.Format("{0,-11}{1}\n", tag, new string(x));
                    }
                    else {
                        result += string.Format("           {0}\n", new string(x));
                    }
                }

                if (count % 16 != 0) {
                    x = new char[(count%16)*2];
                    for (int j = 0; j < count % 16; j++) {
                        x[j * 2] = hex[signatureBytes[offset] >> 4];
                        x[j * 2 + 1] = hex[signatureBytes[offset] & 0xf];
                        offset += 1;
                    }

                    if (count < 16) {
                        result += string.Format("{0,-11}{1}\n", tag, new string(x));
                    }
                    else {
                        result += string.Format("           {0}\n", new string(x));
                    }
                }

                return result;
            }
        }

        class HssNode
        {
            private LmsKey privateKey;

            public HssNode(LmsAlgorithmType lmsType, LmotsAlgorithmType lmotsType)
            {
                privateKey = new LmsKey(lmsType, lmotsType);
            }

            public HssNode(string[] input, int offset)
            {
                privateKey = new LmsKey(input, offset);
            }

            public byte[] PublicKey => privateKey.PublicKey;

            public void GetPrivateKey(StringBuilder sb)
            {
                privateKey.GetPublicKey(sb);
            }

            public byte[] Sign(byte[] message)
            {
                return privateKey.Sign(message);
            }
        }

        public enum LmotsAlgorithmType {
            Sha256_n32_w1 = 1,
            Sha256_n32_w2 = 2,
            Sha256_n32_w4 = 3,
            Sha256_n32_w8 = 4
        }

        public enum LmsAlgorithmType
        {
            Sha256_m32_h5 = 5,
            Sha256_m32_h10 = 6,
            Sha256_m32_h15 = 7,
            Sha256_m32_h20 = 8,
            Sha256_m32_h25 = 9
        }

        private HssNode[] _hssTree;

        public HashSig()
        {

        }

        public HashSig(string privateKey)
        {
            string[] input = privateKey.Split('|');
            int levels = Int32.Parse(input[0]);
            if (input.Length != levels * 5 + 1) {
                throw new CoseException("Not a valid private key");
            }

            _hssTree = new HssNode[levels];
            for (int i = 0; i < levels; i++) {
                _hssTree[i] = new HssNode(input, i*5+1);
            }
        }       

        public void Create(LmsAlgorithmType[] lmsType, LmotsAlgorithmType lmotsType)
        {
            _hssTree = new HssNode[lmsType.Length];
            for (int i = 0; i < lmsType.Length; i++) {
                _hssTree[i] = new HssNode(lmsType[i], lmotsType);
            }
        }

        public string PrivateKey
        {
            get {
                StringBuilder sb = new StringBuilder($"{_hssTree.Length}");

                for (int i = 0; i < _hssTree.Length; i++) {
                    sb.Append("|");
                    _hssTree[i].GetPrivateKey(sb);
                }

                return sb.ToString();
            }
        }

        public byte[] PublicKey
        {
            get {
                byte[] rootKey = _hssTree[0].PublicKey;
                byte[] pubKey = new byte[rootKey.Length + 4];
                Array.Copy(u32str(_hssTree.Length), pubKey, 4);
                Array.Copy(rootKey, 0, pubKey, 4, rootKey.Length);
                return pubKey;
            }
        }

        public byte[] Sign(byte[] message)
        {
            int depth = _hssTree.Length;
            byte[][] allsigs = new byte[depth*2+2][];
            int cb = 4;

            allsigs[0] = u32str(depth-1);
            for (int i = 0; i < depth-1; i++) {
                allsigs[2*i + 1] = _hssTree[i].Sign(_hssTree[i + 1].PublicKey);
                cb += allsigs[i + 1].Length;
                allsigs[2 * i + 2] = _hssTree[i + 1].PublicKey;
                cb += allsigs[2 * i + 2].Length;
            }

            allsigs[depth*2+1] = _hssTree[depth - 1].Sign(message);
            cb += allsigs[depth*2+1].Length;

            byte[] signatureBytes = new byte[cb];
            cb = 0;
            foreach (byte[] val in allsigs) {
                if (val == null) continue;
                Array.Copy(val, 0, signatureBytes, cb, val.Length);
                cb += val.Length;
            }

            return signatureBytes;
        }

        public static bool Validate(byte[] message, byte[] publicKey, byte[] signatureBytes)
        {
            int cb;

            UInt32 nspk = strTou32(signatureBytes, 0);
            UInt32 nspkKey = strTou32(publicKey, 0);
            if (nspk + 1 != nspkKey) {
                throw new CoseException("Incorrect number of signature layeres for the public key");
            }

            byte[][] sigList = new byte[nspk+1][];
            byte[][] publist = new byte[nspk][];
            int offset = 4;

            for (uint i = 0; i < nspk; i++) {
                cb = LmsKey.SignatureLength(signatureBytes, offset);
                sigList[i] = new byte[cb];
                Array.Copy(signatureBytes, offset, sigList[i], 0, cb);
                offset += cb;

                cb = LmsKey.PublicKeyLength(signatureBytes, offset);
                publist[i] = new byte[cb];
                Array.Copy(signatureBytes, offset, publist[i], 0, cb);
                offset += cb;
            }

            cb = LmsKey.SignatureLength(signatureBytes, offset);
            sigList[nspk] = new byte[cb];
            Array.Copy(signatureBytes, offset, sigList[nspk], 0, cb);

            byte[] key =  new byte[ publicKey.Length-4];
            Array.Copy(publicKey, 4, key, 0, key.Length);
            for (uint i = 0; i < nspk; i++) {
                if (!LmsKey.Validate(publist[i], key, sigList[i])) {
                    return false;
                }
                Array.Copy(publist[i], key, publist[i].Length);
            }

            return LmsKey.Validate(message, key, sigList[nspk]);
        }

        public static void SelfTest()
        {
            //  Test Case #1

            byte[] test1PublicKey =
                StringToByteArray(
                "00000002000000050000000461a5d57d37f5e46bfb7520806b07a1b850650e3b31fe4a773ea29a07f09cf2ea30e579f0df58ef8e298da0434cb2b878");
            byte[] test1Signature =
                StringToByteArray(
                "000000010000000500000004d32b56671d7eb98833c49b433c272586bc4a1c8a8970528ffa04b966f9426eb9965a25bfd37f196b9073f3d4a232feb69128ec45146f86292f9dff9610a7bf95a64c7f60f6261a62043f86c70324b7707f5b4a8a6e19c114c7be866d488778a0e05fd5c6509a6e61d559cf1a77a970de927d60c70d3de31a7fa0100994e162a2582e8ff1b10cd99d4e8e413ef469559f7d7ed12c838342f9b9c96b83a4943d1681d84b15357ff48ca579f19f5e71f18466f2bbef4bf660c2518eb20de2f66e3b14784269d7d876f5d35d3fbfc7039a462c716bb9f6891a7f41ad133e9e1f6d9560b960e7777c52f060492f2d7c660e1471e07e72655562035abc9a701b473ecbc3943c6b9c4f2405a3cb8bf8a691ca51d3f6ad2f428bab6f3a30f55dd9625563f0a75ee390e385e3ae0b906961ecf41ae073a0590c2eb6204f44831c26dd768c35b167b28ce8dc988a3748255230cef99ebf14e730632f27414489808afab1d1e783ed04516de012498682212b07810579b250365941bcc98142da13609e9768aaf65de7620dabec29eb82a17fde35af15ad238c73f81bdb8dec2fc0e7f932701099762b37f43c4a3c20010a3d72e2f606be108d310e639f09ce7286800d9ef8a1a40281cc5a7ea98d2adc7c7400c2fe5a101552df4e3cccfd0cbf2ddf5dc6779cbbc68fee0c3efe4ec22b83a2caa3e48e0809a0a750b73ccdcf3c79e6580c154f8a58f7f24335eec5c5eb5e0cf01dcf4439424095fceb077f66ded5bec73b27c5b9f64a2a9af2f07c05e99e5cf80f00252e39db32f6c19674f190c9fbc506d826857713afd2ca6bb85cd8c107347552f30575a5417816ab4db3f603f2df56fbc413e7d0acd8bdd81352b2471fc1bc4f1ef296fea1220403466b1afe78b94f7ecf7cc62fb92be14f18c2192384ebceaf8801afdf947f698ce9c6ceb696ed70e9e87b0144417e8d7baf25eb5f70f09f016fc925b4db048ab8d8cb2a661ce3b57ada67571f5dd546fc22cb1f97e0ebd1a65926b1234fd04f171cf469c76b884cf3115cce6f792cc84e36da58960c5f1d760f32c12faef477e94c92eb75625b6a371efc72d60ca5e908b3a7dd69fef0249150e3eebdfed39cbdc3ce9704882a2072c75e13527b7a581a556168783dc1e97545e31865ddc46b3c957835da252bb7328d3ee2062445dfb85ef8c35f8e1f3371af34023cef626e0af1e0bc017351aae2ab8f5c612ead0b729a1d059d02bfe18efa971b7300e882360a93b025ff97e9e0eec0f3f3f13039a17f88b0cf808f488431606cb13f9241f40f44e537d302c64a4f1f4ab949b9feefadcb71ab50ef27d6d6ca8510f150c85fb525bf25703df7209b6066f09c37280d59128d2f0f637c7d7d7fad4ed1c1ea04e628d221e3d8db77b7c878c9411cafc5071a34a00f4cf07738912753dfce48f07576f0d4f94f42c6d76f7ce973e9367095ba7e9a3649b7f461d9f9ac1332a4d1044c96aefee67676401b64457c54d65fef6500c59cdfb69af7b6dddfcb0f086278dd8ad0686078dfb0f3f79cd893d314168648499898fbc0ced5f95b74e8ff14d735cdea968bee7400000005d8b8112f9200a5e50c4a262165bd342cd800b8496810bc716277435ac376728d129ac6eda839a6f357b5a04387c5ce97382a78f2a4372917eefcbf93f63bb59112f5dbe400bd49e4501e859f885bf0736e90a509b30a26bfac8c17b5991c157eb5971115aa39efd8d564a6b90282c3168af2d30ef89d51bf14654510a12b8a144cca1848cf7da59cc2b3d9d0692dd2a20ba3863480e25b1b85ee860c62bf51360000000500000004d2f14ff6346af964569f7d6cb880a1b66c5004917da6eafe4d9ef6c6407b3db0e5485b122d9ebe15cda93cfec582d7ab0000000a000000040703c491e7558b35011ece3592eaa5da4d918786771233e8353bc4f62323185c95cae05b899e35dffd717054706209988ebfdf6e37960bb5c38d7657e8bffeef9bc042da4b4525650485c66d0ce19b317587c6ba4bffcc428e25d08931e72dfb6a120c5612344258b85efdb7db1db9e1865a73caf96557eb39ed3e3f426933ac9eeddb03a1d2374af7bf77185577456237f9de2d60113c23f846df26fa942008a698994c0827d90e86d43e0df7f4bfcdb09b86a373b98288b7094ad81a0185ac100e4f2c5fc38c003c1ab6fea479eb2f5ebe48f584d7159b8ada03586e65ad9c969f6aecbfe44cf356888a7b15a3ff074f771760b26f9c04884ee1faa329fbf4e61af23aee7fa5d4d9a5dfcf43c4c26ce8aea2ce8a2990d7ba7b57108b47dabfbeadb2b25b3cacc1ac0cef346cbb90fb044beee4fac2603a442bdf7e507243b7319c9944b1586e899d431c7f91bcccc8690dbf59b28386b2315f3d36ef2eaa3cf30b2b51f48b71b003dfb08249484201043f65f5a3ef6bbd61ddfee81aca9ce60081262a00000480dcbc9a3da6fbef5c1c0a55e48a0e729f9184fcb1407c31529db268f6fe50032a363c9801306837fafabdf957fd97eafc80dbd165e435d0e2dfd836a28b354023924b6fb7e48bc0b3ed95eea64c2d402f4d734c8dc26f3ac591825daef01eae3c38e3328d00a77dc657034f287ccb0f0e1c9a7cbdc828f627205e4737b84b58376551d44c12c3c215c812a0970789c83de51d6ad787271963327f0a5fbb6b5907dec02c9a90934af5a1c63b72c82653605d1dcce51596b3c2b45696689f2eb382007497557692caac4d57b5de9f5569bc2ad0137fd47fb47e664fcb6db4971f5b3e07aceda9ac130e9f38182de994cff192ec0e82fd6d4cb7f3fe00812589b7a7ce515440456433016b84a59bec6619a1c6c0b37dd1450ed4f2d8b584410ceda8025f5d2d8dd0d2176fc1cf2cc06fa8c82bed4d944e71339ece780fd025bd41ec34ebff9d4270a3224e019fcb444474d482fd2dbe75efb20389cc10cd600abb54c47ede93e08c114edb04117d714dc1d525e11bed8756192f929d15462b939ff3f52f2252da2ed64d8fae88818b1efa2c7b08c8794fb1b214aa233db3162833141ea4383f1a6f120be1db82ce3630b3429114463157a64e91234d475e2f79cbf05e4db6a9407d72c6bff7d1198b5c4d6aad2831db61274993715a0182c7dc8089e32c8531deed4f7431c07c02195eba2ef91efb5613c37af7ae0c066babc69369700e1dd26eddc0d216c781d56e4ce47e3303fa73007ff7b949ef23be2aa4dbf25206fe45c20dd888395b2526391a724996a44156beac808212858792bf8e74cba49dee5e8812e019da87454bff9e847ed83db07af313743082f880a278f682c2bd0ad6887cb59f652e155987d61bbf6a88d36ee93b6072e6656d9ccbaae3d655852e38deb3a2dcf8058dc9fb6f2ab3d3b3539eb77b248a661091d05eb6e2f297774fe6053598457cc61908318de4b826f0fc86d4bb117d33e865aa805009cc2918d9c2f840c4da43a703ad9f5b5806163d7161696b5a0adc00000005d5c0d1bebb06048ed6fe2ef2c6cef305b3ed633941ebc8b3bec9738754cddd60e1920ada52f43d055b5031cee6192520d6a5115514851ce7fd448d4a39fae2ab2335b525f484e9b40d6a4a969394843bdcf6d14c48e8015e08ab92662c05c6e9f90b65a7a6201689999f32bfd368e5e3ec9cb70ac7b8399003f175c40885081a09ab3034911fe125631051df0408b3946b0bde790911e8978ba07dd56c73e7ee");
            byte[] test1Message = Encoding.UTF8.GetBytes(
                "The powers not delegated to the United States by the Constitution, nor prohibited by it to the States, are reserved to the States respectively, or to the people.\n");

            if (!Validate(test1Message, test1PublicKey, test1Signature)) throw new Exception("Self test fail 1");

            //  Test Case #2
            byte[] test2PublicKey =
                StringToByteArray(
                    "000000020000000600000003d08fabd4a2091ff0a8cb4ed834e7453432a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e");
            byte[] test2Signature = StringToByteArray(
                "0000000100000003000000033d46bee8660f8f215d3f96408a7a64cf1c4da02b63a55f62c666ef5707a914ce0674e8cb7a55f0c48d484f31f3aa4af9719a74f22cf823b94431d01c926e2a76bb71226d279700ec81c9e95fb11a0d10d065279a5796e265ae17737c44eb8c594508e126a9a7870bf4360820bdeb9a01d9693779e416828e75bddd7d8c70d50a0ac8ba39810909d445f44cb5bb58de737e60cb4345302786ef2c6b14af212ca19edeaa3bfcfe8baa6621ce88480df2371dd37add732c9de4ea2ce0dffa53c92649a18d39a50788f4652987f226a1d48168205df6ae7c58e049a25d4907edc1aa90da8aa5e5f7671773e941d8055360215c6b60dd35463cf2240a9c06d694e9cb54e7b1e1bf494d0d1a28c0d31acc75161f4f485dfd3cb9578e836ec2dc722f37ed30872e07f2b8bd0374eb57d22c614e09150f6c0d8774a39a6e168211035dc52988ab46eaca9ec597fb18b4936e66ef2f0df26e8d1e34da28cbb3af752313720c7b345434f72d65314328bbb030d0f0f6d5e47b28ea91008fb11b05017705a8be3b2adb83c60a54f9d1d1b2f476f9e393eb5695203d2ba6ad815e6a111ea293dcc21033f9453d49c8e5a6387f588b1ea4f706217c151e05f55a6eb7997be09d56a326a32f9cba1fbe1c07bb49fa04cecf9df1a1b815483c75d7a27cc88ad1b1238e5ea986b53e087045723ce16187eda22e33b2c70709e53251025abde8939645fc8c0693e97763928f00b2e3c75af3942d8ddaee81b59a6f1f67efda0ef81d11873b59137f67800b35e81b01563d187c4a1575a1acb92d087b517a8833383f05d357ef4678de0c57ff9f1b2da61dfde5d88318bcdde4d9061cc75c2de3cd4740dd7739ca3ef66f1930026f47d9ebaa713b07176f76f953e1c2e7f8f271a6ca375dbfb83d719b1635a7d8a13891957944b1c29bb101913e166e11bd5f34186fa6c0a555c9026b256a6860f4866bd6d0b5bf90627086c6149133f8282ce6c9b3622442443d5eca959d6c14ca8389d12c4068b503e4e3c39b635bea245d9d05a2558f249c9661c0427d2e489ca5b5dde220a90333f4862aec793223c781997da98266c12c50ea28b2c438e7a379eb106eca0c7fd6006e9bf612f3ea0a454ba3bdb76e8027992e60de01e9094fddeb3349883914fb17a9621ab929d970d101e45f8278c14b032bcab02bd15692d21b6c5c204abbf077d465553bd6eda645e6c3065d33b10d518a61e15ed0f092c32226281a29c8a0f50cde0a8c66236e29c2f310a375cebda1dc6bb9a1a01dae6c7aba8ebedc6371a7d52aacb955f83bd6e4f84d2949dcc198fb77c7e5cdf6040b0f84faf82808bf985577f0a2acf2ec7ed7c0b0ae8a270e951743ff23e0b2dd12e9c3c828fb5598a22461af94d568f29240ba2820c4591f71c088f96e095dd98beae456579ebbba36f6d9ca2613d1c26eee4d8c73217ac5962b5f3147b492e8831597fd89b64aa7fde82e1974d2f6779504dc21435eb3109350756b9fdabe1c6f368081bd40b27ebcb9819a75d7df8bb07bb05db1bab705a4b7e37125186339464ad8faaa4f052cc1272919fde3e025bb64aa8e0eb1fcbfcc25acb5f718ce4f7c2182fb393a1814b0e942490e52d3bca817b2b26e90d4c9b0cc38608a6cef5eb153af0858acc867c9922aed43bb67d7b33acc519313d28d41a5c6fe6cf3595dd5ee63f0a4c4065a083590b275788bee7ad875a7f88dd73720708c6c6c0ecf1f43bbaadae6f208557fdc07bd4ed91f88ce4c0de842761c70c186bfdafafc444834bd3418be4253a71eaf41d718753ad07754ca3effd5960b0336981795721426803599ed5b2b7516920efcbe32ada4bcf6c73bd29e3fa152d9adeca36020fdeeee1b739521d3ea8c0da497003df1513897b0f54794a873670b8d93bcca2ae47e64424b7423e1f078d9554bb5232cc6de8aae9b83fa5b9510beb39ccf4b4e1d9c0f19d5e17f58e5b8705d9a6837a7d9bf99cd13387af256a8491671f1f2f22af253bcff54b673199bdb7d05d81064ef05f80f0153d0be7919684b23da8d42ff3effdb7ca0985033f389181f47659138003d712b5ec0a614d31cc7487f52de8664916af79c98456b2c94a8038083db55391e3475862250274a1de2584fec975fb09536792cfbfcf6192856cc76eb5b13dc4709e2f7301ddff26ec1b23de2d188c999166c74e1e14bbc15f457cf4e471ae13dcbdd9c50f4d646fc6278e8fe7eb6cb5c94100fa870187380b777ed19d7868fd8ca7ceb7fa7d5cc861c5bdac98e7495eb0a2ceec1924ae979f44c5390ebedddc65d6ec11287d978b8df064219bc5679f7d7b264a76ff272b2ac9f2f7cfc9fdcfb6a51428240027afd9d52a79b647c90c2709e060ed70f87299dd798d68f4fadd3da6c51d839f851f98f67840b964ebe73f8cec41572538ec6bc131034ca2894eb736b3bda93d9f5f6fa6f6c0f03ce43362b8414940355fb54d3dfdd03633ae108f3de3ebc85a3ff51efeea3bc2cf27e1658f1789ee612c83d0f5fd56f7cd071930e2946beeecaa04dccea9f97786001475e0294bc2852f62eb5d39bb9fbeef75916efe44a662ecae37ede27e9d6eadfdeb8f8b2b2dbccbf96fa6dbaf7321fb0e701f4d429c2f4dcd153a2742574126e5eaccc77686acf6e3ee48f423766e0fc466810a905ff5453ec99897b56bc55dd49b991142f65043f2d744eeb935ba7f4ef23cf80cc5a8a335d3619d781e7454826df720eec82e06034c44699b5f0c44a8787752e057fa3419b5bb0e25d30981e41cb1361322dba8f69931cf42fad3f3bce6ded5b8bfc3d20a2148861b2afc14562ddd27f12897abf0685288dcc5c4982f826026846a24bf77e383c7aacab1ab692b29ed8c018a65f3dc2b87ff619a633c41b4fadb1c78725c1f8f922f6009787b1964247df0136b1bc614ab575c59a16d089917bd4a8b6f04d95c581279a139be09fcf6e98a470a0bceca191fce476f9370021cbc05518a7efd35d89d8577c990a5e19961ba16203c959c91829ba7497cffcbb4b294546454fa5388a23a22e805a5ca35f956598848bda678615fec28afd5da61a00000006b326493313053ced3876db9d237148181b7173bc7d042cefb4dbe94d2e58cd21a769db4657a103279ba8ef3a629ca84ee836172a9c50e51f45581741cf8083150b491cb4ecbbabec128e7c81a46e62a67b57640a0a78be1cbf7dd9d419a10cd8686d16621a80816bfdb5bdc56211d72ca70b81f1117d129529a7570cf79cf52a7028a48538ecdd3b38d3d5d62d26246595c4fb73a525a5ed2c30524ebb1d8cc82e0c19bc4977c6898ff95fd3d310b0bae71696cef93c6a552456bf96e9d075e383bb7543c675842bafbfc7cdb88483b3276c29d4f0a341c2d406e40d4653b7e4d045851acf6a0a0ea9c710b805cced4635ee8c107362f0fc8d80c14d0ac49c516703d26d14752f34c1c0d2c4247581c18c2cf4de48e9ce949be7c888e9caebe4a415e291fd107d21dc1f084b1158208249f28f4f7c7e931ba7b3bd0d824a45700000000500000004215f83b7ccb9acbcd08db97b0d04dc2ba1cd035833e0e90059603f26e07ad2aad152338e7a5e5984bcd5f7bb4eba40b700000004000000040eb1ed54a2460d512388cad533138d240534e97b1e82d33bd927d201dfc24ebb11b3649023696f85150b189e50c00e98850ac343a77b3638319c347d7310269d3b7714fa406b8c35b021d54d4fdada7b9ce5d4ba5b06719e72aaf58c5aae7aca057aa0e2e74e7dcfd17a0823429db62965b7d563c57b4cec942cc865e29c1dad83cac8b4d61aacc457f336e6a10b66323f5887bf3523dfcadee158503bfaa89dc6bf59daa82afd2b5ebb2a9ca6572a6067cee7c327e9039b3b6ea6a1edc7fdc3df927aade10c1c9f2d5ff446450d2a3998d0f9f6202b5e07c3f97d2458c69d3c8190643978d7a7f4d64e97e3f1c4a08a7c5bc03fd55682c017e2907eab07e5bb2f190143475a6043d5e6d5263471f4eecf6e2575fbc6ff37edfa249d6cda1a09f797fd5a3cd53a066700f45863f04b6c8a58cfd341241e002d0d2c0217472bf18b636ae547c1771368d9f317835c9b0ef430b3df4034f6af00d0da44f4af7800bc7a5cf8a5abdb12dc718b559b74cab9090e33cc58a955300981c420c4da8ffd67df540890a062fe40dba8b2c1c548ced22473219c534911d48ccaabfb71bc71862f4a24ebd376d288fd4e6fb06ed8705787c5fedc813cd2697e5b1aac1ced45767b14ce88409eaebb601a93559aae893e143d1c395bc326da821d79a9ed41dcfbe549147f71c092f4f3ac522b5cc57290706650487bae9bb5671ecc9ccc2ce51ead87ac01985268521222fb9057df7ed41810b5ef0d4f7cc67368c90f573b1ac2ce956c365ed38e893ce7b2fae15d3685a3df2fa3d4cc098fa57dd60d2c9754a8ade980ad0f93f6787075c3f680a2ba1936a8c61d1af52ab7e21f416be09d2a8d64c3d3d8582968c2839902229f85aee297e717c094c8df4a23bb5db658dd377bf0f4ff3ffd8fba5e383a48574802ed545bbe7a6b4753533353d73706067640135a7ce517279cd683039747d218647c86e097b0daa2872d54b8f3e5085987629547b830d8118161b65079fe7bc59a99e9c3c7380e3e70b7138fe5d9be2551502b698d09ae193972f27d40f38dea264a0126e637d74ae4c92a6249fa103436d3eb0d4029ac712bfc7a5eacbdd7518d6d4fe903a5ae65527cd65bb0d4e9925ca24fd7214dc617c150544e423f450c99ce51ac8005d33acd74f1bed3b17b7266a4a3bb86da7eba80b101e15cb79de9a207852cf91249ef480619ff2af8cabca83125d1faa94cbb0a03a906f683b3f47a97c871fd513e510a7a25f283b196075778496152a91c2bf9da76ebe089f4654877f2d586ae7149c406e663eadeb2b5c7e82429b9e8cb4834c83464f079995332e4b3c8f5a72bb4b8c6f74b0d45dc6c1f79952c0b7420df525e37c15377b5f0984319c3993921e5ccd97e097592064530d33de3afad5733cbe7703c5296263f77342efbf5a04755b0b3c997c4328463e84caa2de3ffdcd297baaaacd7ae646e44b5c0f16044df38fabd296a47b3a838a913982fb2e370c078edb042c84db34ce36b46ccb76460a690cc86c302457dd1cde197ec8075e82b393d542075134e2a17ee70a5e187075d03ae3c853cff60729ba4000000054de1f6965bdabc676c5a4dc7c35f97f82cb0e31c68d04f1dad96314ff09e6b3de96aeee300d1f68bf1bca9fc58e4032336cd819aaf578744e50d1357a0e4286704d341aa0a337b19fe4bc43c2e79964d4f351089f2e0e41c7c43ae0d49e7f404b0f75be80ea3af098c9752420a8ac0ea2bbb1f4eeba05238aef0d8ce63f0c6e5e4041d95398a6f7f3e0ee97cc1591849d4ed236338b147abde9f51ef9fd4e1c1");
            byte[] test2Message = Encoding.UTF8.GetBytes(
                "The enumeration in the Constitution, of certain rights, shall not be construed to deny or disparage others retained by the people.\n");
            if (!Validate(test2Message, test2PublicKey, test2Signature)) throw new Exception("Self test fail 2");

            byte[] test3PublicKey =
                StringToByteArray(
                    "000000010000000600000003d08fabd4a2091ff0a8cb4ed834e7453432a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e");
            string test3PrivateKey =
                    "1|" + // Two Levels
                    "6|3|" + // First Level - LM_SHA256_MD32_H10 + LMOTS_SHA256_N32_W4
                    // "D41073216E3A81162F7C32C987006518E2FFAF0F34EEE089FD9870D8F148B750|" +
                    "558B8966C48AE9CB898B423C83443AAE014A72F1B1AB5CC85CF1D892903B5439|" +
                    //                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f|" + // SEED Level 1
                    "0|" + // q=2
                    "d08fabd4a2091ff0a8cb4ed834e74534" // Identifier Level 1
                ;
            HashSig hashKey = new HashSig(test3PrivateKey);
            byte[] mySignature = hashKey.Sign(test2Message);
            string foo = PrintSignature(mySignature);

            if (!Validate(test2Message, test3PublicKey, mySignature)) {
                throw new Exception("Verify of signature failed");
            }

            test3PublicKey = StringToByteArray(
                "000000020000000600000003d08fabd4a2091ff0a8cb4ed834e7453432a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e");
            test3PrivateKey =
                    "2|" + // Two Levels
                    "6|3|" + // First Level - LM_SHA256_MD32_H10 + LMOTS_SHA256_N32_W4
                    "558B8966C48AE9CB898B423C83443AAE014A72F1B1AB5CC85CF1D892903B5439|" +
//                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f|" + // SEED Level 1
                    "2|" + // q=2
                    "d08fabd4a2091ff0a8cb4ed834e74534|" + // Identifier Level 1
                    "5|4|" + // Second Level - LM_SHA256_M32_H5 + LM_SHA256_N32_W8
                    "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f00|" + // SEED Level 2
                    "3|" + // q=3
                    "215f83b7ccb9acbcd08db97b0d04dc2b" // Identifier Level 2
                ;

            hashKey = new HashSig(test3PrivateKey);
            if (!test3PublicKey.SequenceEqual(hashKey.PublicKey)) {
                throw new Exception("Public Key did not match");
            }

            mySignature = hashKey.Sign(test2Message);

            foo = PrintSignature(mySignature);

            if (!Validate(test2Message, test3PublicKey, mySignature)) {
                throw new Exception("Verify of signature failed");
            }
        }

        public static string PrintSignature(byte[] signatureBytes)
        {
            UInt32 nspk = strTou32(signatureBytes, 0);
            string result = "";
            int offset = 4;

            for (uint i = 0; i < nspk; i++) {
                result += LmsKey.PrintSignature(signatureBytes, ref offset);
                result += LmsKey.PrintPublicKey(signatureBytes, ref offset);
            }

            result +=
                "------------------------------------------------\nfinal signature:\n-----------------------------------";
            result += LmsKey.PrintSignature(signatureBytes, ref offset);

            return result;
        }

        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                .ToArray();
        }

        private static byte[] u32str(Int32 i)
        {
            byte[] bytes = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(bytes);
            }

            return bytes;
        }

        private static byte[] u32str(UInt32 i)
        {
            byte[] bytes = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(bytes);
            }

            return bytes;
        }

        private static UInt32 strTou32(byte[] data, int offset)
        {
            byte[] bytes = new byte[4];
            Array.Copy(data, offset, bytes, 0, 4);
            if (BitConverter.IsLittleEndian) {
                Array.Reverse(bytes);
            }

            return BitConverter.ToUInt32(bytes, 0);
        }
    }
}
