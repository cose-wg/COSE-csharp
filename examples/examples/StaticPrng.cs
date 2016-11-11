using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Security;

using PeterO.Cbor;


namespace examples
{
    public class StaticPrng :  SecureRandom
    {
        byte[] m_rgbRngData = new byte[0];
        int m_iRngData;
        SecureRandom m_prng = null;
        bool m_fDirty = false;
        CBORObject objNew = CBORObject.NewArray();

        /// <summary>Add more seed material to the generator.</summary>
        /// <param name="seed">A byte array to be mixed into the generator's state.</param>
        public void AddSeedMaterial(byte[] seed)
        {
            m_rgbRngData = m_rgbRngData.Concat(seed).ToArray();
            m_iRngData = 0;
        }

        /// <summary>Add more seed material to the generator.</summary>
        /// <param name="seed">A long value to be mixed into the generator's state.</param>
        public void AddSeedMaterial(long seed)
        {
            throw new Exception("Don't call this function");
        }

        /// <summary>Fill byte array with random values.</summary>
        /// <param name="bytes">Array to be filled.</param>
        override public void NextBytes(byte[] bytes)
        {
            NextBytes(bytes, 0, bytes.Length);
        }

        /// <summary>Fill byte array with random values.</summary>
        /// <param name="bytes">Array to receive bytes.</param>
        /// <param name="start">Index to start filling at.</param>
        /// <param name="len">Length of segment to fill.</param>
        override public void NextBytes(byte[] bytes, int start, int len)
        {

            if (m_iRngData + len > m_rgbRngData.Length) {
                if (m_prng == null) m_prng = new SecureRandom();

                int cbOld = m_rgbRngData.Length;
                Array.Resize(ref m_rgbRngData, m_iRngData + len);
                m_prng.NextBytes(m_rgbRngData, cbOld, m_rgbRngData.Length - cbOld);
                m_fDirty = true;
            }

            Array.Copy(m_rgbRngData, m_iRngData, bytes, start, len);

            byte[] x = new byte[len];
            Array.Copy(m_rgbRngData, m_iRngData, x, 0, len);
            objNew.Add(CBORObject.FromObject(Program.ToHex(x)));

            m_iRngData += len;

        }

        public CBORObject buffer { get { if (m_iRngData == 0) return null; else return objNew; } }
        public bool IsDirty { get { return m_fDirty || (m_iRngData != m_rgbRngData.Length) || true; } }
        public void Reset() { m_iRngData = 0; }
    }
}
