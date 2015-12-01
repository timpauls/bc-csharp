using System;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;

namespace Org.BouncyCastle.Crypto.Generators
{
	public class SraKeyParametersGenerator
	{
		private int size;
		private int certainty;
		private SecureRandom random;

		/// <summary>Initialize the parameters generator.</summary>
		/// <param name="size">the bit-length for the modulus</param>
		/// <param name="certainty">level of certainty for the prime number tests</param>
		/// <param name="random">a source if randomness</param>
		public void Init(int size, int certainty, SecureRandom random)
		{
			this.size = size;
			this.certainty = certainty;
			this.random = random;
		}

		/// <summary>Generates the p and q values from the given parameters, returning the SrakeyGenerationParameters object.</summary>
		public SraKeyGenerationParameters GenerateParameters() {
			int mindiffbits = this.size / 3;
			int minWeight = this.size >> 2;

			while (true) {
				BigInteger p;
				while (true) {
					p = new BigInteger(this.size / 2, this.certainty, this.random);

					if (p.IsProbablePrime(this.certainty)) {
						break;
					}
				}

				BigInteger q;
				while (true) {
					q = new BigInteger(this.size / 2, this.certainty, this.random);

					if (q.IsProbablePrime(this.certainty) && !q.Equals(p)) {
						break;
					}
				}

				// p and q should not be too close together (or equal!)
				BigInteger diff = q.Subtract(p).Abs();
				if (diff.BitLength < mindiffbits) {
					//              System.out.println("p and q too close together or equal.");
					continue;
				}

				// modulus has to be strong enough.
				BigInteger n = p.Multiply(q);

				/*
	             * Require a minimum weight of the NAF representation, since low-weight composites may
	             * be weak against a version of the number-field-sieve for factoring.
	             *
	             * See "The number field sieve for integers of low weight", Oliver Schirokauer.
	             */
				if (WNafUtilities.GetNafWeight(n) < minWeight) {
					continue;
				}

				if (n.BitLength == this.size) {
					return new SraKeyGenerationParameters(p, q, this.random, this.size, this.certainty);
				}
			}
		}
	}
}

