using System;
using Org.BouncyCastle.Math;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class SraKeyParameters
	{
		private BigInteger p;
		private BigInteger q;
		private BigInteger e;
		private BigInteger d;

		public SraKeyParameters(BigInteger p, BigInteger q, BigInteger e, BigInteger d) {
			this.p = p;
			this.q = q;
			this.e = e;
			this.d = d;
		}

		public BigInteger P {
			get { return p; }
		}

		public BigInteger Q {
			get { return q; }
		}

		public BigInteger E {
			get { return e; }
		}

		public BigInteger D {
			get { return d; }
		}
	}
}

