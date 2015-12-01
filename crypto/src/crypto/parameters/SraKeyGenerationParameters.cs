using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Parameters
{
	public class SraKeyGenerationParameters
		: KeyGenerationParameters
	{
		private readonly BigInteger p;
		private readonly BigInteger q;
		private readonly int certainty;

		public SraKeyGenerationParameters(
			BigInteger		p,
			BigInteger		q,
			SecureRandom	random,
			int				strength,
			int				certainty)
			: base(random, strength)
		{
			this.p = p;
			this.q = q;
			this.certainty = certainty;

			if (!p.IsProbablePrime(certainty)) {
				throw new ArgumentException("p is probably NOT prime!");
			}

			if (!q.IsProbablePrime(certainty)) {
				throw new ArgumentException("q is probably NOT prime!");
			}

			BigInteger n = p.Multiply(q);
			if (n.BitLength != strength) {
				throw new ArgumentException("p and q are not strong enough!");
			}

			int mindiffbits = strength / 3;
			BigInteger diff = q.Subtract(p).Abs();
			if (diff.BitLength < mindiffbits) {
				throw new ArgumentException("p and q lie too close together!");
			}

			/*
	         * Require a minimum weight of the NAF representation, since low-weight composites may
	         * be weak against a version of the number-field-sieve for factoring.
	         *
	         * See "The number field sieve for integers of low weight", Oliver Schirokauer.
	         */
			int minWeight = strength >> 2;
			if (WNafUtilities.GetNafWeight(n) < minWeight) {
				throw new ArgumentException("NAF weight not high enough!");
			}
		}

		public BigInteger P
		{
			get { return p; }
		}

		public BigInteger Q
		{
			get { return q; }
		}

		public int Certainty
		{
			get { return certainty; }
		}

		public override bool Equals(
			object obj)
		{
			SraKeyGenerationParameters other = obj as SraKeyGenerationParameters;

			if (other == null)
			{
				return false;
			}

			return certainty == other.certainty
				&& p.Equals(other.P)
				&& q.Equals(other.Q);
		}

		public override int GetHashCode()
		{
			return certainty.GetHashCode() ^ p.GetHashCode() ^ q.GetHashCode();
		}
	}
}
