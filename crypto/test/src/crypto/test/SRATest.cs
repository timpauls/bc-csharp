using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;
using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class SRATest
        : SimpleTest
    {

        static int KEY_SIZE_IN_BIT = 2048;
        static int CERTAINTY = 80;
        static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

        //
        // to check that we handling byte extension by big number correctly.
        //
        static String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

        private SecureRandom secureRandom = null;
		private SraKeyParametersGenerator keyParamGenerator;

        public override string Name
        {
            get
            {
                return "SRA";
            }
        }

        private void setUp()
        {
            this.secureRandom = SecureRandom.GetInstance("SHA1PRNG");
			this.keyParamGenerator = new SraKeyParametersGenerator();
			this.keyParamGenerator.Init(KEY_SIZE_IN_BIT, CERTAINTY, secureRandom);
        }

        

        public override void PerformTest()
        {
			setUp();

            testSRAEngineNotInitializedException();
            testSRAEngineDataLengthException();
            testKeyParameterGeneration();
			testEncryptionDecryption();
			testCommutativity();
        }

        private void testSRAEngineNotInitializedException()
        {
            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);

            SraEngine sraEngine = new SraEngine();
            try
            {
                sraEngine.ProcessBlock(inputBytes, 0, inputBytes.Length);
                Fail("failed - unitialized SRAEngine did not throw exception");
            }
            catch (Exception e)
            {
                if (e.Message.Contains("RSA"))
                {
                    Fail("failed - exception message contains wrong algorithm", e);
                }
            }
        }

        private void testSRAEngineDataLengthException()
        {
            byte[] inputBytes = System.Text.Encoding.UTF8.GetBytes(input);

            SraKeyParametersGenerator sraKeyParametersGenerator = new SraKeyParametersGenerator();
            sraKeyParametersGenerator.Init(12, 5, this.secureRandom);
            SraKeyGenerationParameters sraKeyGenerationParameters = sraKeyParametersGenerator.GenerateParameters();
            SraKeyPairGenerator SraKeyPairGenerator = new SraKeyPairGenerator();
            SraKeyPairGenerator.Init(sraKeyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = SraKeyPairGenerator.GenerateKeyPair();

            SraEngine sraEngine = new SraEngine();
            sraEngine.Init(true, asymmetricCipherKeyPair.Public);

            try
            {
                sraEngine.ProcessBlock(inputBytes, 0, inputBytes.Length);
                Fail("failed - failed to recognize too large input for modulus");
            }
            catch (DataLengthException e)
            {
                if (e.Message.Contains("RSA"))
                {
                    Fail("failed - exception message contains wrong algorithm", e);
                }
            }
        }

        private void testKeyParameterGeneration()
        {
            try
            {
                SraKeyParametersGenerator generator = new SraKeyParametersGenerator();
                generator.Init(KEY_SIZE_IN_BIT, CERTAINTY, this.secureRandom);
                generator.GenerateParameters();
            }
            catch (ArgumentException e)
            {
                Fail("key parameter generation failed", e);
            }
        }

        private void testEncryptionDecryption()
        {
            SraKeyPairGenerator sraKeyPairGenerator = new SraKeyPairGenerator();
            SraKeyGenerationParameters sraKeyGenerationParameters = keyParamGenerator.GenerateParameters();
            sraKeyPairGenerator.Init(sraKeyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = sraKeyPairGenerator.GenerateKeyPair();

            byte[] data = Hex.Decode(edgeInput);

            SraEngine sraEngine = new SraEngine();
            sraEngine.Init(true, asymmetricCipherKeyPair.Public);
            byte[] cipher = sraEngine.ProcessBlock(data, 0, data.Length);

            sraEngine.Init(false, asymmetricCipherKeyPair.Private);
            byte[] decrypted = sraEngine.ProcessBlock(cipher, 0, cipher.Length);

            if (!Arrays.AreEqual(data, decrypted))
            {
                Fail("failed - decryption does not equal original data!");
            }
        }

        /**
        * Test commutativity:
        * Da(Eb(Ea(M))) = Eb(M)
        */
        private void testCommutativity()
        {
            // Alice
            SraKeyPairGenerator sraKeyPairGeneratorAlice = new SraKeyPairGenerator();
            SraKeyGenerationParameters parameters = keyParamGenerator.GenerateParameters();
            sraKeyPairGeneratorAlice.Init(parameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPairAlice = sraKeyPairGeneratorAlice.GenerateKeyPair();

            // Bob
            SraKeyPairGenerator sraKeyPairGeneratorBob = new SraKeyPairGenerator();

            sraKeyPairGeneratorBob.Init(new SraKeyGenerationParameters(parameters.P, parameters.Q, this.secureRandom, KEY_SIZE_IN_BIT, CERTAINTY));
            AsymmetricCipherKeyPair asymmetricCipherKeyPairBob = sraKeyPairGeneratorBob.GenerateKeyPair();

            byte[] data = Hex.Decode(edgeInput);
            SraEngine sraEngine = new SraEngine();

            // Encode first with Alice's key, then with Bob's
            sraEngine.Init(true, asymmetricCipherKeyPairAlice.Public);
            byte[] cipherAlice = sraEngine.ProcessBlock(data, 0, data.Length);

            sraEngine.Init(true, asymmetricCipherKeyPairBob.Public);
            byte[] cipherAliceBob = sraEngine.ProcessBlock(cipherAlice, 0, cipherAlice.Length);

            // decrypt with Alice's key
            sraEngine.Init(false, asymmetricCipherKeyPairAlice.Private);
            byte[] decryptedAlice = sraEngine.ProcessBlock(cipherAliceBob, 0, cipherAliceBob.Length);

            // encrypt plaintext just with Bob's key
            sraEngine.Init(true, asymmetricCipherKeyPairBob.Public);
            byte[] cipherBob = sraEngine.ProcessBlock(data, 0, data.Length);

            if (!Arrays.AreEqual(decryptedAlice, cipherBob))
            {
                Fail("failed - encryption is not commutative!");
            }
        }

		private void restoreKeyAndUseIt() {
			SraKeyPairGenerator sraKeyPairGenerator = new SraKeyPairGenerator();
			SraKeyGenerationParameters sraKeyGenerationParameters = keyParamGenerator.GenerateParameters();
			sraKeyPairGenerator.Init(sraKeyGenerationParameters);
			AsymmetricCipherKeyPair asymmetricCipherKeyPair = sraKeyPairGenerator.GenerateKeyPair();

			SraKeyParameters sraKeyParameters = SraKeyParameterExtractor.ExtractParameters(asymmetricCipherKeyPair);

			// Create another Keypair
			AsymmetricCipherKeyPair keyPair2 = SraKeyPairGenerator.CreateKeyPair(sraKeyParameters);

			// Try encryption and decryption
			byte[] data = Hex.Decode(edgeInput);

			// Original key
			SraEngine engine = new SraEngine();
			engine.Init(true, asymmetricCipherKeyPair.Public);
			byte[] ciphertext = engine.ProcessBlock(data, 0, data.Length);

			engine.Init(false, asymmetricCipherKeyPair.Private);
			byte[] plaintext = engine.ProcessBlock(ciphertext, 0, ciphertext.Length);

			if (!Arrays.AreEqual(plaintext, data)) {
				Fail("fail - decrypton with original key failed to restore original plain text");
			}

			// Restored key
			engine.Init(true, keyPair2.Public);
			byte[] ciphertext2 = engine.ProcessBlock(data, 0, data.Length);

			engine.Init(false, keyPair2.Private);
			byte[] plaintext2 = engine.ProcessBlock(ciphertext2, 0, ciphertext2.Length);

			if (!Arrays.AreEqual(plaintext2, data)) {
				Fail("fail - decrypton with restored key failed to restore original plain text");
			}

			// Encryption with original, decryption with restored key
			engine.Init(true, asymmetricCipherKeyPair.Public);
			byte[] ciphertext3 = engine.ProcessBlock(data, 0, data.Length);

			engine.Init(false, keyPair2.Private);
			byte[] plaintext3 = engine.ProcessBlock(ciphertext3, 0, ciphertext3.Length);

			if (!Arrays.AreEqual(plaintext3, data)) {
				Fail("fail - decrypton with restored key failed to restore original plain text encrypted with original key");
			}
		}
    }
}
