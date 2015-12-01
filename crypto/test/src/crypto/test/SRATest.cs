using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Test;
using System;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Tests
{
    public class SRATest
        : SimpleTest
    {

        static int KEY_SIZE = 2048;
        static int CERTAINTY = 80;
        static String input = "4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

        //
        // to check that we handling byte extension by big number correctly.
        //
        static String edgeInput = "ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e";

        SecureRandom random = null;

        public override string Name
        {
            get
            {
                return "SRA";
            }
        }

        private void setUp()
        {
            this.random = new SecureRandom();

        }

        

        public override void PerformTest()
        {
            testSRAEngineNotInitializedException();
            testSRAEngineDataLengthException();
            testKeyParameterGeneration();
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

            SRAKeyParametersGenerator sraKeyParametersGenerator = new SRAKeyParametersGenerator();
            sraKeyParametersGenerator.Init(12, 5, this.random);
            SRAKeyGenerationParameters sraKeyGenerationParameters = sraKeyParametersGenerator.GenerateParameters();
            SRAKeyPairGenerator sraKeyPairGenerator = new SRAKeyPairGenerator();
            sraKeyPairGenerator.Init(sraKeyGenerationParameters);
            AsymmetricCipherKeyPair asymmetricCipherKeyPair = sraKeyPairGenerator.GenerateKeyPair();

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
                SRAKeyParametersGenerator generator = new SRAKeyParametersGenerator();
                generator.Init(KEY_SIZE, CERTAINTY, this.random);
                generator.GenerateParameters();
            }
            catch (ArgumentException e)
            {
                Fail("key parameter generation failed", e);
            }
        }

        private void testEncryptionDecryption()
        {
            SRAKeyPairGenerator sraKeyPairGenerator = new SRAKeyPairGenerator();
            SRAKeyGenerationParameters sraKeyGenerationParameters = keyParamGenerator.GenerateParameters();
            sraKeyPairGenerator.init(sraKeyGenerationParameters);
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
            SRAKeyPairGenerator sraKeyPairGeneratorAlice = new SRAKeyPairGenerator();
            SRAKeyGenerationParameters params = keyParamGenerator.GenerateParameters();
            sraKeyPairGeneratorAlice.Init(params);
            AsymmetricCipherKeyPair asymmetricCipherKeyPairAlice = sraKeyPairGeneratorAlice.GenerateKeyPair();

            // Bob
            SRAKeyPairGenerator sraKeyPairGeneratorBob = new SRAKeyPairGenerator();

            sraKeyPairGeneratorBob.init(new SRAKeyGenerationParameters(params.P, params.Q, this.random, KEY_SIZE, CERTAINTY));
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
    }
}
