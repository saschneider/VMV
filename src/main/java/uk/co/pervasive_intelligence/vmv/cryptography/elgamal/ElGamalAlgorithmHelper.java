/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.elgamal;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.pervasive_intelligence.vmv.cryptography.AlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.BaseHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * ElGamal implementation of the {@link AlgorithmHelper}.
 *
 * Uses Bouncy Castle's implementation.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ElGamalAlgorithmHelper extends BaseHelper implements AlgorithmHelper {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ElGamalAlgorithmHelper.class);

  /**
   * Uses the algorithm to create keys.
   *
   * @param random     Source of randomness.
   * @param parameters The created algorithm parameters.
   * @return The created keys.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public KeyPair createKeys(final SecureRandom random, final Parameters parameters) throws CryptographyException {
    try {
      // Convert the DH parameters.
      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final ElGamalParameters elgamalParameters = new ElGamalParameters(dhParametersWrapper.getP(), dhParametersWrapper.getG(), dhParametersWrapper.getL());

      // Generate the key pair using the parameters.
      final ElGamalKeyPairGenerator generator = new ElGamalKeyPairGenerator();
      generator.init(new ElGamalKeyGenerationParameters(random, elgamalParameters));

      LOG.debug("Generating ElGamal keys");
      final AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
      return new KeyPair(((ElGamalPrivateKeyParameters) keyPair.getPrivate()).getX(), ((ElGamalPublicKeyParameters) keyPair.getPublic()).getY());
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create ElGamal key pair", e);
    }
  }

  /**
   * Generates parameters for the algorithm.
   *
   * @param random Source of randomness.
   * @param values Specific values of parameters to be used.
   * @return The corresponding algorithm parameters.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public Parameters createParameters(final SecureRandom random, final Object... values) throws CryptographyException {
    try {
      // Convert the parameter values, filling in defaults where needed.
      int keyLengthL = DEFAULT_LENGTH_L;
      int certainty = DEFAULT_PRIME_CERTAINTY;

      if (values != null) {
        if (values.length >= 1) {
          keyLengthL = (int) values[0];
        }
        if (values.length >= 2) {
          certainty = (int) values[1];
        }
      }

      // We use the DHParametersGenerator which does the same thing as the ElGamalParametersGenerator, but allows us to obtain q, which is otherwise discarded.
      final DHParametersGenerator parameterGenerator = new DHParametersGenerator();
      parameterGenerator.init(keyLengthL, certainty, random);

      LOG.debug("Generating ElGamal parameters");
      final DHParameters parameters = parameterGenerator.generateParameters();

      // Wrap the parameters in an object which can be serialised.
      return new DHParametersWrapper(parameters);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create ElGamal parameters", e);
    }
  }

  /**
   * Decrypts the ciphertext data using the parameters and key pair. Only relevant if the algorithm can be used to encrypt/decrypt.
   *
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data which has been encrypted.
   * @return The decrypted plaintext.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public byte[] decrypt(final Parameters parameters, final KeyPair keyPair, final byte[] data) throws CryptographyException {
    // Make sure we have a private key.
    if (keyPair.getPrivateKey() == null) {
      throw new CryptographyException("Missing private key");
    }

    try {
      LOG.debug("ElGamal decrypt");

      // We do not use the Bouncy Castle implementation explicitly since Verificatum requires the two terms of the ciphertext independently. Instead we perform the
      // calculation manually.
      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final BigInteger p = dhParametersWrapper.getP();
      final CipherText cipherText = new CipherText(data);

      // Use the shortcut defined in Bouncy Castle.
      final BigInteger numberInGroup =
          cipherText.getAlpha().modPow(p.subtract(BigInteger.ONE).subtract(keyPair.getPrivateKey()), p).multiply(cipherText.getBeta()).mod(p);
      return numberInGroup.toByteArray();
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not ElGamal decrypt", e);
    }
  }

  /**
   * Encrypts the plaintext data using the parameters and key pair. Only relevant if the algorithm can be used to encrypt/decrypt.
   *
   * @param random     Source of randomness.
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data to sign.
   * @return The ciphertext for the plaintext together with any other values: here the randomness used during encryption.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public byte[][] encrypt(final SecureRandom random, final Parameters parameters, final KeyPair keyPair, final byte[] data) throws CryptographyException {
    // Make sure we have a public key.
    if (keyPair.getPublicKey() == null) {
      throw new CryptographyException("Missing public key");
    }

    try {
      LOG.debug("ElGamal encrypt");

      // We do not use the Bouncy Castle implementation explicitly since Verificatum requires the two terms of the ciphertext independently. Instead we perform the
      // calculation manually.
      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final BigInteger p = dhParametersWrapper.getP();
      final BigInteger g = dhParametersWrapper.getG();

      // Convert the data into a number that should be within the group G of the parameters.
      final BigInteger numberInGroup = new BigInteger(1, data);

      if (numberInGroup.compareTo(p) >= 0) {
        throw new CryptographyException("Number too large to be in group");
      }

      // Generate a random number in the range 1 to p-1.
      final BigInteger k = this.generateRandom(random, p);

      // Calculate alpha as g^k mod p.
      final BigInteger alpha = g.modPow(k, p);

      // Calculate beta as numberInGroup * h^k mod p, where h is the public key.
      final BigInteger beta = keyPair.getPublicKey().modPow(k, p).multiply(numberInGroup).mod(p);

      return new byte[][] {(new CipherText(alpha, beta)).toByteArray(), k.toByteArray()};
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not ElGamal encrypt", e);
    }
  }

  /**
   * Generates a non-interactive zero-knowledge proof of knowledge of the witness and one or more statements.
   *
   * @param random     Source of randomness.
   * @param parameters The created algorithm parameters.
   * @param witness    The (private) witness of the statement.
   * @param statements The statements being proved.
   * @return The corresponding proof.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public Proof generateProof(final SecureRandom random, final Parameters parameters, final BigInteger witness, final Statement... statements) throws CryptographyException {
    throw new CryptographyException("ElGamal algorithm cannot be used for non-interactive zero-knowledge proof of knowledge");
  }

  /**
   * @return The class used for the parameters.
   */
  @Override
  public Class<? extends Parameters> getParametersClass() {
    return DHParametersWrapper.class;
  }

  /**
   * Signs the specified data using the parameters and key pair. Only relevant if the algorithm can be used to sign/verify.
   *
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data to sign.
   * @return The signature for the data.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public byte[] sign(final Parameters parameters, final KeyPair keyPair, final byte[] data) throws CryptographyException {
    throw new CryptographyException("ElGamal algorithm cannot be used for sign/verify");
  }

  /**
   * Verifies the signature of the data using the parameters and key pair. Only relevant if the algorithm can be used to sign/verify.
   *
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data which has been signed.
   * @param signature  The signature to verify.
   * @return True if the signature matches, false otherwise.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public boolean verify(final Parameters parameters, final KeyPair keyPair, final byte[] data, final byte[] signature) throws CryptographyException {
    throw new CryptographyException("ElGamal algorithm cannot be used for sign/verify");
  }

  /**
   * Verifies a non-interactive zero-knowledge proof of knowledge of one or more statements given their proof.
   *
   * @param parameters The created algorithm parameters.
   * @param proof      The proof of knowledge to verify.
   * @param statements The statements being proved.
   * @return True if the proof of knowledge is verified, false otherwise.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public boolean verifyProof(final Parameters parameters, final Proof proof, final Statement... statements) throws CryptographyException {
    throw new CryptographyException("ElGamal algorithm cannot be used for non-interactive zero-knowledge proof of knowledge");
  }
}
