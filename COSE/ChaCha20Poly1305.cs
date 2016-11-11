using System;
using System.IO;
using System.Text;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities;

using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Math;

namespace COSE
{
    public class ChaCha20Poly1305 : IAeadBlockCipher
    {
        /// <summary>
        /// Poly1305 message authentication code, designed by D. J. Bernstein.
        /// </summary>
        /// <remarks>
        /// Poly1305 computes a 128-bit (16 bytes) authenticator, using a 128 bit nonce and a 256 bit key
        /// consisting of a 128 bit key applied to an underlying cipher, and a 128 bit key (with 106
        /// effective key bits) used in the authenticator.
        /// 
        /// The polynomial calculation in this implementation is adapted from the public domain <a
        /// href="https://github.com/floodyberry/poly1305-donna">poly1305-donna-unrolled</a> C implementation
        /// by Andrew M (@floodyberry).
        /// </remarks>
        /// <seealso cref="Org.BouncyCastle.Crypto.Generators.Poly1305KeyGenerator"/>
        public class Poly1305
            : IMac
        {
            private const int BLOCK_SIZE = 16;

            private readonly byte[] singleByte = new byte[1];

            // Initialised state

            BigInteger r;
            BigInteger s;
            BigInteger a;
            static BigInteger p = new BigInteger(new byte[] { 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb });


            /** Current block of buffered input */
            private byte[] currentBlock = new byte[BLOCK_SIZE];

            /** Current offset in input buffer */
            private int currentBlockOffset = 0;


            /**
             * Constructs a Poly1305 MAC, where the key passed to init() will be used directly.
             */
            public Poly1305()
            {
            }

            /// <summary>
            /// Initialises the Poly1305 MAC.
            /// </summary>
            /// <param name="parameters">a {@link ParametersWithIV} containing a 128 bit nonce and a {@link KeyParameter} with
            ///          a 256 bit key complying to the {@link Poly1305KeyGenerator Poly1305 key format}.</param>
            public void Init(ICipherParameters parameters)
            {
                byte[] nonce = null;

                if (!(parameters is KeyParameter))
                    throw new ArgumentException("Poly1305 requires a key.");

                KeyParameter keyParams = (KeyParameter) parameters;

                SetKey(keyParams.GetKey(), nonce);

                Reset();
            }

            static BigInteger clamp = new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
            private void SetKey(byte[] key, byte[] nonce)
            {
                byte[] z = new byte[key.Length];
                Array.Copy(key, z, key.Length);
                Array.Reverse(z);
                // Extract r portion of key
                r = new BigInteger(1, z, 16, 16);
                r = r.And(clamp);
                s = new BigInteger(1, z, 0, 16);
            }

            public string AlgorithmName
            {
                get { return "Poly1305"; }
            }

            public int GetMacSize()
            {
                return BLOCK_SIZE;
            }

            public void Update(byte input)
            {
                singleByte[0] = input;
                BlockUpdate(singleByte, 0, 1);
            }

            public void BlockUpdate(byte[] input, int inOff, int len)
            {
                int copied = 0;
                while (len > copied) {
                    if (currentBlockOffset == BLOCK_SIZE) {
                        processBlock();
                        currentBlockOffset = 0;
                    }

                    int toCopy = System.Math.Min((len - copied), BLOCK_SIZE - currentBlockOffset);
                    Array.Copy(input, copied + inOff, currentBlock, currentBlockOffset, toCopy);
                    copied += toCopy;
                    currentBlockOffset += toCopy;
                }

            }

            static BigInteger HighBit = new BigInteger(new byte[] { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 });
            private void processBlock()
            {
                if (currentBlockOffset < BLOCK_SIZE) {
                    currentBlock[currentBlockOffset] = 1;
                    for (int i = currentBlockOffset + 1; i < BLOCK_SIZE; i++) {
                        currentBlock[i] = 0;
                    }
                }

                Array.Reverse(currentBlock);
                BigInteger n = new BigInteger(1, currentBlock);
                if (currentBlockOffset == BLOCK_SIZE) {
                    n = n.Add(HighBit);
                }

                a = a.Add(n);
                a = r.Multiply(a);
                a = a.Mod(p);
            }

            public int DoFinal(byte[] output, int outOff)
            {
                if (outOff + BLOCK_SIZE > output.Length) {
                    throw new DataLengthException("Output buffer is too short.");
                }

                if (currentBlockOffset > 0) {
                    // Process padded block
                    processBlock();
                }

                a = a.Add(s);

                byte[] value = a.ToByteArrayUnsigned();
                Array.Reverse(value);
                Array.Copy(value, 0, output, outOff, BLOCK_SIZE);
                Reset();
                return BLOCK_SIZE;
            }

            public void Reset()
            {
                currentBlockOffset = 0;
                a = new BigInteger(new byte[1] { 0 });
            }
        }

        class ChaChaX : ChaChaEngine
        {
            public override void Init(bool forEncryption, ICipherParameters parameters)
            {
                base.Init(forEncryption, parameters);
            }

            override protected int NonceSize
            {
                get { return 12; }
            }
            public void AddOne()
            {
                AdvanceCounter();
            }

            protected override void AdvanceCounter()
            {
                ++engineState[12];
            }

            override protected void SetKey(byte[] keyBytes, byte[] ivBytes)
            {
                if ((keyBytes.Length != 32)) {
                    throw new ArgumentException(AlgorithmName + " requires 256 bit key");
                }

                int offset = 0;
                byte[] constants;

                // Key
                engineState[4] = Pack.LE_To_UInt32(keyBytes, 0);
                engineState[5] = Pack.LE_To_UInt32(keyBytes, 4);
                engineState[6] = Pack.LE_To_UInt32(keyBytes, 8);
                engineState[7] = Pack.LE_To_UInt32(keyBytes, 12);

                    constants = sigma;
                    offset = 16;

                engineState[8] = Pack.LE_To_UInt32(keyBytes, offset);
                engineState[9] = Pack.LE_To_UInt32(keyBytes, offset + 4);
                engineState[10] = Pack.LE_To_UInt32(keyBytes, offset + 8);
                engineState[11] = Pack.LE_To_UInt32(keyBytes, offset + 12);

                engineState[0] = Pack.LE_To_UInt32(constants, 0);
                engineState[1] = Pack.LE_To_UInt32(constants, 4);
                engineState[2] = Pack.LE_To_UInt32(constants, 8);
                engineState[3] = Pack.LE_To_UInt32(constants, 12);

                // Counter
                engineState[12] = 0;

                // IV
                engineState[13] = Pack.LE_To_UInt32(ivBytes, 0);
                engineState[14] = Pack.LE_To_UInt32(ivBytes, 4);
                engineState[15] = Pack.LE_To_UInt32(ivBytes, 8);
                ResetCounter();
            }
        }

        private const int BlockSize = 16;
        private const int macSize = 16;

        private readonly IBlockCipher cipher;

        //  These fields are set by Init and not modified by processing
        private bool forEncryption;
        private byte[] nonce;
        private byte[] initialAssociatedText;

        private Poly1305 poly;
        private ChaChaX chacha20;

        //  These fields are modified during processing

        private byte[] macResult;
        private int bufOff;
        private int aadLength;

        private readonly MemoryStream data = new MemoryStream();

        public ChaCha20Poly1305()
        {

        }

        public virtual string AlgorithmName
        {
            get { return "ChaCha20/Poly1305"; }
        }

        public IBlockCipher GetUnderlyingCipher()
        {
            return cipher;
        }

        public virtual int GetBlockSize()
        {
            return BlockSize;
        }

        public virtual void Init(
            bool forEncryption,
            ICipherParameters parameters)
        {
            this.forEncryption = forEncryption;

            KeyParameter keyParam;

            if (parameters is AeadParameters) {
                AeadParameters param = (AeadParameters) parameters;

                nonce = param.GetNonce();
                initialAssociatedText = param.GetAssociatedText();

                keyParam = param.Key;
            }
            else if (parameters is ParametersWithIV) {
                ParametersWithIV param = (ParametersWithIV) parameters;

                nonce = param.GetIV();
                initialAssociatedText = null;
                keyParam = (KeyParameter) param.Parameters;
            }
            else {
                throw new ArgumentException("invalid parameters passed to ChaCha20Poly1305");
            }

            if (nonce == null || nonce.Length <1) {
                throw new ArgumentException("IV must be at least 1 byte");
            }

            //  Geneate the key 
            ChaChaX tmpCypher = new ChaChaX();
            byte[] zero = new byte[32];
            byte[] polyKey = new byte[32];
            ParametersWithIV tmpKey =  new ParametersWithIV( keyParam, nonce);
            tmpCypher.Init(true, tmpKey);
            tmpCypher.ProcessBytes(zero, 0, zero.Length, polyKey, 0);

            poly = new Poly1305();

            KeyParameter tmpKey2 = new KeyParameter(polyKey);
            poly.Init(tmpKey2);

            chacha20 = new ChaChaX();
            chacha20.Init(forEncryption, tmpKey);

            InitCipher();

        }

        private void InitCipher()
        {
            this.aadLength = 0;

            poly.Reset();
            chacha20.Reset();
            chacha20.AddOne();
            data.SetLength(0);

            if (initialAssociatedText != null) {
                ProcessAadBytes(initialAssociatedText, 0, initialAssociatedText.Length);
            }
        }

        public virtual byte[] GetMac()
        {
            return macResult;
        }

        public virtual int GetOutputSize(int len)
        {
            int totalData = len + bufOff;

            if (forEncryption) {
                return totalData + macSize;
            }
            return totalData < macSize ? 0 : totalData - macSize;
        }

        public virtual int GetUpdateOutputSize(int len)
        {
            int totalData = len + bufOff;
            if (!forEncryption) {
                if (totalData < macSize) { return 0; }
                totalData -= macSize;
            }
            return totalData - totalData % BlockSize;
        }

        public virtual void ProcessAadByte(byte input)
        {
            poly.Update(input);
            aadLength += 1;
        }

        public virtual void ProcessAadBytes(byte[] inBytes, int inOff, int len)
        {
            poly.BlockUpdate(inBytes, inOff, len);
            aadLength += len;
        }

        public virtual int ProcessByte(byte input, byte[] output, int outOff)
        {
            data.WriteByte(input);
            return 0;
        }

        public virtual int ProcessBytes(byte[] input, int inOff, int len, byte[] output, int outOff)
        {
            data.Write(input, inOff, len);
            return 0;
        }

        public int DoFinal(byte[] output, int outOff)
        {
            byte[] zeros;

            if (data.Length + aadLength == 0) {
                InitCipher();
            }

            int extra = (int) data.Length;

            if (forEncryption) {
                // Check.OutputLength(output, outOff, bufOff, extra + macSize, "Output buffer too short");
            }
            else {
                if (extra < macSize) throw new InvalidCipherTextException("data too short");

                extra -= macSize;

                // Check.OutputLength(output, outOff, extra, "Output buffer too short");
            }

            //  Pad out the AD

                zeros = new byte[16 - (aadLength % 16)];
                if (zeros.Length != 16) poly.BlockUpdate(zeros, 0, zeros.Length);

            chacha20.ProcessBytes(data.GetBuffer(), 0, extra, output, outOff);

            if (forEncryption) {
                poly.BlockUpdate(output, outOff, extra);
            }
            else {
                poly.BlockUpdate(data.GetBuffer(), 0, extra);
            }

            int resultLen = 0;

            zeros = new byte[16 - (extra % 16)];
            if (zeros.Length != 16) poly.BlockUpdate(zeros, 0, zeros.Length);

            byte[] lengths = BitConverter.GetBytes((Int64) aadLength);
            poly.BlockUpdate(lengths, 0, lengths.Length);
            lengths = BitConverter.GetBytes((Int64) extra);
            poly.BlockUpdate(lengths, 0, lengths.Length);

            macResult = new byte[macSize];
            if (poly.DoFinal(macResult, 0) != macResult.Length) throw new Exception("Internal Error");

            if (forEncryption) {
                resultLen = extra + macSize;
                Array.Copy(macResult, 0, output, extra+outOff, macSize);
            }
            else {
                bool f = true;
                for (int i=0; i<macSize; i++) {
                    f &= (macResult[i] == data.GetBuffer()[extra + i]);
                }
                if (!f) throw new Exception("Authentication Failed");
                resultLen = extra;
            }

            Reset(false);

            return resultLen;
        }

        public virtual void Reset()
        {
            Reset(true);
        }

        private void Reset(bool clearMac)
        {
            if (clearMac) {
                macResult = null;
            }
            data.SetLength(0);
            chacha20.Reset();
            poly.Reset();
            aadLength = 0;
        }


        public static void SelfTest()
        {
            byte[] key = new byte[] {
                0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6, 0xb5, 0xf0,
                0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc, 0x20, 0x70, 0x75, 0xc0
            };

            byte[] nonce = new byte[] {
                0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
            };

            byte[] cipherText = new byte[] {
                0x64,  0xa0, 0x86, 0x15, 0x75, 0x86, 0x1a, 0xf4, 0x60, 0xf0, 0x62, 0xc7, 0x9b, 0xe6, 0x43, 0xbd,
                0x5e , 0x80 , 0x5c , 0xfd , 0x34 , 0x5c , 0xf3 , 0x89 , 0xf1 , 0x08 , 0x67 , 0x0a , 0xc7 , 0x6c , 0x8c , 0xb2,
                0x4c, 0x6c , 0xfc , 0x18 , 0x75 , 0x5d , 0x43 , 0xee , 0xa0 , 0x9e , 0xe9 , 0x4e , 0x38 , 0x2d , 0x26 , 0xb0,
                0xbd , 0xb7 , 0xb7 , 0x3c , 0x32 , 0x1b , 0x01 , 0x00 , 0xd4 , 0xf0 , 0x3b , 0x7f , 0x35 , 0x58 , 0x94 , 0xcf,
                0x33 , 0x2f , 0x83 , 0x0e , 0x71 , 0x0b , 0x97 , 0xce , 0x98 , 0xc8 , 0xa8 , 0x4a , 0xbd , 0x0b , 0x94 , 0x81,
                0x14 , 0xad , 0x17 , 0x6e , 0x00 , 0x8d , 0x33 , 0xbd , 0x60 , 0xf9 , 0x82 , 0xb1 , 0xff , 0x37 , 0xc8 , 0x55,
                0x97 , 0x97 , 0xa0 , 0x6e , 0xf4 , 0xf0 , 0xef , 0x61 , 0xc1 , 0x86 , 0x32 , 0x4e , 0x2b , 0x35 , 0x06 , 0x38,
                0x36 , 0x06 , 0x90 , 0x7b , 0x6a , 0x7c , 0x02 , 0xb0 , 0xf9 , 0xf6 , 0x15 , 0x7b , 0x53 , 0xc8 , 0x67 , 0xe4,
                0xb9 , 0x16 , 0x6c , 0x76 , 0x7b , 0x80 , 0x4d , 0x46 , 0xa5 , 0x9b , 0x52 , 0x16 , 0xcd , 0xe7 , 0xa4 , 0xe9,
                0x90 , 0x40 , 0xc5 , 0xa4 , 0x04 , 0x33 , 0x22 , 0x5e , 0xe2 , 0x82 , 0xa1 , 0xb0 , 0xa0 , 0x6c , 0x52 , 0x3e,
                0xaf , 0x45 , 0x34 , 0xd7 , 0xf8 , 0x3f , 0xa1 , 0x15 , 0x5b , 0x00 , 0x47 , 0x71 , 0x8c , 0xbc , 0x54 , 0x6a,
                0x0d , 0x07 , 0x2b , 0x04 , 0xb3 , 0x56 , 0x4e , 0xea , 0x1b , 0x42 , 0x22 , 0x73 , 0xf5 , 0x48 , 0x27 , 0x1a,
                0x0b , 0xb2 , 0x31 , 0x60 , 0x53 , 0xfa , 0x76 , 0x99 , 0x19 , 0x55 , 0xeb , 0xd6 , 0x31 , 0x59 , 0x43 , 0x4e,
                0xce , 0xbb , 0x4e , 0x46 , 0x6d , 0xae , 0x5a , 0x10 , 0x73 , 0xa6 , 0x72 , 0x76 , 0x27 , 0x09 , 0x7a , 0x10,
                0x49 , 0xe6 , 0x17 , 0xd9 , 0x1d , 0x36 , 0x10 , 0x94 , 0xfa , 0x68 , 0xf0 , 0xff , 0x77 , 0x98 , 0x71 , 0x30,
                0x30 , 0x5b , 0xea , 0xba , 0x2e , 0xda , 0x04 , 0xdf , 0x99 , 0x7b , 0x71 , 0x4d , 0x6c , 0x6f , 0x2c , 0x29,
                0xa6 , 0xad , 0x5c , 0xb4 , 0x02 , 0x2b , 0x02 , 0x70 , 0x9b,
                0xee, 0xad, 0x9d, 0x67, 0x89, 0x0c, 0xbb, 0x22, 0x39, 0x23, 0x36, 0xfe, 0xa1, 0x85, 0x1f, 0x38
            };

            byte[] aad = new byte[] {
                0xf3, 0x33, 0x88, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4e, 0x91
            };

            byte[] plainText = new byte[] {
                0x49, 0x6e , 0x74 , 0x65 , 0x72 , 0x6e , 0x65 , 0x74 , 0x2d , 0x44 , 0x72 , 0x61 , 0x66 , 0x74 , 0x73 , 0x20,
                0x61 , 0x72 , 0x65 , 0x20 , 0x64 , 0x72 , 0x61 , 0x66 , 0x74 , 0x20 , 0x64 , 0x6f , 0x63 , 0x75 , 0x6d , 0x65,
                0x6e , 0x74 , 0x73 , 0x20 , 0x76 , 0x61 , 0x6c , 0x69 , 0x64 , 0x20 , 0x66 , 0x6f , 0x72 , 0x20 , 0x61 , 0x20,
                0x6d , 0x61 , 0x78 , 0x69 , 0x6d , 0x75 , 0x6d , 0x20 , 0x6f , 0x66 , 0x20 , 0x73 , 0x69 , 0x78 , 0x20 , 0x6d,
                0x6f , 0x6e , 0x74 , 0x68 , 0x73 , 0x20 , 0x61 , 0x6e , 0x64 , 0x20 , 0x6d , 0x61 , 0x79 , 0x20 , 0x62 , 0x65,
                0x20 , 0x75 , 0x70 , 0x64 , 0x61 , 0x74 , 0x65 , 0x64 , 0x2c , 0x20 , 0x72 , 0x65 , 0x70 , 0x6c , 0x61 , 0x63,
                0x65 , 0x64 , 0x2c , 0x20 , 0x6f , 0x72 , 0x20 , 0x6f , 0x62 , 0x73 , 0x6f , 0x6c , 0x65 , 0x74 , 0x65 , 0x64,
                0x20 , 0x62 , 0x79 , 0x20 , 0x6f , 0x74 , 0x68 , 0x65 , 0x72 , 0x20 , 0x64 , 0x6f , 0x63 , 0x75 , 0x6d , 0x65,
                0x6e , 0x74 , 0x73 , 0x20 , 0x61 , 0x74 , 0x20 , 0x61 , 0x6e , 0x79 , 0x20 , 0x74 , 0x69 , 0x6d , 0x65 , 0x2e,
                0x20 , 0x49 , 0x74 , 0x20 , 0x69 , 0x73 , 0x20 , 0x69 , 0x6e , 0x61 , 0x70 , 0x70 , 0x72 , 0x6f , 0x70 , 0x72,
                0x69 , 0x61 , 0x74 , 0x65 , 0x20 , 0x74 , 0x6f , 0x20 , 0x75 , 0x73 , 0x65 , 0x20 , 0x49 , 0x6e , 0x74 , 0x65,
                0x72 , 0x6e , 0x65 , 0x74 , 0x2d , 0x44 , 0x72 , 0x61, 0x66 , 0x74 , 0x73 , 0x20 , 0x61 , 0x73 , 0x20 , 0x72,
                0x65 , 0x66 , 0x65 , 0x72, 0x65 , 0x6e , 0x63 , 0x65 , 0x20 , 0x6d , 0x61 , 0x74 , 0x65 , 0x72 , 0x69 , 0x61,
                0x6c , 0x20 , 0x6f , 0x72 , 0x20 , 0x74 , 0x6f , 0x20 , 0x63 , 0x69 , 0x74 , 0x65 , 0x20 , 0x74 , 0x68 , 0x65,
                0x6d , 0x20 , 0x6f , 0x74 , 0x68 , 0x65 , 0x72 , 0x20 , 0x74 , 0x68 , 0x61 , 0x6e , 0x20 , 0x61 , 0x73 , 0x20,
                0x2f , 0xe2 , 0x80 , 0x9c , 0x77 , 0x6f , 0x72 , 0x6b , 0x20 , 0x69 , 0x6e , 0x20 , 0x70 , 0x72 , 0x6f , 0x67,
                0x72 , 0x65 , 0x73 , 0x73 , 0x2e , 0x2f , 0xe2 , 0x80 , 0x9d
            };

            Poly1305 p = new Poly1305();
            byte[] pKey = new byte[] { 0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49, 0xf5, 0x1b
            };
            KeyParameter paramsX = new KeyParameter(pKey);
            p.Init(paramsX);

            byte[] msg = UTF8Encoding.ASCII.GetBytes("Cryptographic Forum Research Group");
            p.BlockUpdate(msg, 0, msg.Length);
            byte[] output = new byte[30];
            p.DoFinal(output, 0);


            ChaCha20Poly1305 cipher = new ChaCha20Poly1305();

            KeyParameter ContentKey = new KeyParameter(key);
            AeadParameters parameters = new AeadParameters(ContentKey, 128, nonce, aad);

            cipher.Init(true, parameters);

            byte[] C = new byte[cipher.GetOutputSize(plainText.Length)];
            int len = cipher.ProcessBytes(plainText, 0, plainText.Length, C, 0);
            len += cipher.DoFinal(C, len);


        }
    }
}
