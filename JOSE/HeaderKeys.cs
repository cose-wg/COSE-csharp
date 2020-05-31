using PeterO.Cbor;

namespace Com.AugustCellars.JOSE
{
    public class HeaderKeys
    {
        public static readonly CBORObject Algorithm = CBORObject.FromObject("alg");
        public static readonly CBORObject ContentType = CBORObject.FromObject("cty");
        public static readonly CBORObject Critical = CBORObject.FromObject("crit");
        public static readonly CBORObject EncryptionAlgorithm = CBORObject.FromObject("enc");
        public static readonly CBORObject KeyIdentifier = CBORObject.FromObject("kid");
        public static readonly CBORObject Type = CBORObject.FromObject("typ");
    }
}
