using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Generators
{
	/**
     * an SRA key pair generator.
     */
	public class SraKeyPairGenerator
		:   IAsymmetricCipherKeyPairGenerator
	{
		protected static readonly BigInteger One = BigInteger.One;

		protected SraKeyGenerationParameters parameters;

		public virtual void Init(
			KeyGenerationParameters parameters)
		{
			this.parameters = (SraKeyGenerationParameters) parameters;
		}

		public virtual AsymmetricCipherKeyPair GenerateKeyPair()
		{
			AsymmetricCipherKeyPair result;
			BigInteger p, q, n, d, e, pSub1, qSub1, gcd, lcm;

			p = parameters.P;
			q = parameters.Q;
			n = p.Multiply(q);

			// d lower bound is 2^(strength / 
			BigInteger dLowerBound = BigInteger.ValueOf(2).Pow(parameters.Strength / 2);

			if (p.CompareTo(q) < 0)
			{
				gcd = p;
				p = q;
				q = gcd;
			}

			pSub1 = p.Subtract(One);
			qSub1 = q.Subtract(One);
			gcd = pSub1.Gcd(qSub1);
			lcm = pSub1.Divide(gcd).Multiply(qSub1);

			bool done = false;
			do {
				e = chooseRandomPublicExponent(pSub1.Multiply(qSub1));

				//
				// calculate the private exponent
				//
				d = e.ModInverse(lcm);

				done = d.CompareTo(dLowerBound) > 0;

//            if (!done) {
//                System.out.println("ERROR: d too small. should be " + dLowerBound.toString(10) + " but is " + d.toString(10));
//            }
			} while (!done);

			//
			// calculate the CRT factors
			//
			BigInteger dP, dQ, qInv;

			dP = d.Remainder(pSub1);
			dQ = d.Remainder(qSub1);
			qInv = q.ModInverse(p);

			result = new AsymmetricCipherKeyPair(
				new RsaKeyParameters(false, n, e),
				new RsaPrivateCrtKeyParameters(n, e, d, p, q, dP, dQ, qInv));

			return result;
		}

		/// <summary>Choose a random public exponent to use with SRA.</summary>
		/// <param name="phiN">(p-1)*(q-1)</param>
		/// <returns>an exponent e, with 1 < e < phiN</returns>
		private BigInteger chooseRandomPublicExponent(BigInteger phiN)
		{
			for (;;)
			{
				BigInteger e = new BigInteger(phiN.BitLength, parameters.Random);
				if (!e.Gcd(phiN).Equals(One)) {
					continue;
				}

				if (e.CompareTo(One) <= 0) {
					continue;
				}

				if (e.CompareTo(phiN) >= 0) {
					continue;
				}

				return e;
			}
		}
	}
}
