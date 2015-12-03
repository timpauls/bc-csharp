using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Utilities
{
	public class SraKeyParameterExtractor
	{
		public static SraKeyParameters ExtractParameters(AsymmetricCipherKeyPair keyPair) {
			if (!(keyPair.Public is RsaKeyParameters)) {
				throw new ArgumentException("not an sra key-pair.");
			}

			if (!(keyPair.Private is RsaPrivateCrtKeyParameters)) {
				throw new ArgumentException("not an sra key-pair");
			}


			RsaKeyParameters pub = (RsaKeyParameters) keyPair.Public;
			RsaPrivateCrtKeyParameters priv = (RsaPrivateCrtKeyParameters) keyPair.Private;

			if (!(pub.Modulus.Equals(priv.Modulus))) {
				throw new ArgumentException("not an valid sra key-pair. modulus is different.");
			}

			return new SraKeyParameters(priv.P, priv.Q, priv.PublicExponent, priv.Exponent);
		}
	}
}

