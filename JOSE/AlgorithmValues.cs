using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public class AlgorithmValues
    {
        public static readonly CBORObject AES_GCM_128 = CBORObject.FromObject("A128GCM");
        public static readonly CBORObject AES_GCM_192 = CBORObject.FromObject("A128GCM");

        public static readonly CBORObject ECDSA_256 = CBORObject.FromObject("ES256");

        public static readonly CBORObject ECDH_ES_HKDF_256_AES_KW_128 = CBORObject.FromObject("ECDH-ES+A128KW");
    }
}
