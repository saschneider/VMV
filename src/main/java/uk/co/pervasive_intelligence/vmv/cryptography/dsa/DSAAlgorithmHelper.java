/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.dsa;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.DSAKeyPairGenerator;
import org.bouncycastle.crypto.generators.DSAParametersGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.DSASigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.pervasive_intelligence.vmv.cryptography.AlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.BaseHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * DSA implementation of the {@link AlgorithmHelper}.
 *
 * Uses Bouncy Castle's implementation which follows NIST FIPS PUB 186-4:
 *
 * NIST (2013). Federal Information Processing Standards Publication: Digital Signature Standard (DSS), FIPS PUB 186-4.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class DSAAlgorithmHelper extends BaseHelper implements AlgorithmHelper {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(DSAAlgorithmHelper.class);

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
      final DSAParameters dsaParameters = new DSAParameters(dhParametersWrapper.getP(), dhParametersWrapper.getQ(), dhParametersWrapper.getG());

      // Generate the key pair using the parameters.
      final DSAKeyPairGenerator generator = new DSAKeyPairGenerator();
      generator.init(new DSAKeyGenerationParameters(random, dsaParameters));

      LOG.debug("Generating DSA keys");
      final AsymmetricCipherKeyPair keyPair = generator.generateKeyPair();
      return new KeyPair(((DSAPrivateKeyParameters) keyPair.getPrivate()).getX(), ((DSAPublicKeyParameters) keyPair.getPublic()).getY());
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create DSA key pair", e);
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
      int keyLengthN = DEFAULT_LENGTH_N;
      int certainty = DEFAULT_PRIME_CERTAINTY;

      if (values != null) {
        if (values.length >= 1) {
          keyLengthL = (int) values[0];
        }
        if (values.length >= 2) {
          keyLengthN = (int) values[1];
        }
        if (values.length >= 3) {
          certainty = (int) values[2];
        }
      }

      // Explicitly create the DSA key generator using the required parameters. This follows NIST (2013) A.1.1.2.
      final DSAParameterGenerationParameters generatorParameters = new DSAParameterGenerationParameters(keyLengthL, keyLengthN, certainty, random);
      final DSAParametersGenerator parameterGenerator = new DSAParametersGenerator(this.digestForLength(keyLengthN));
      parameterGenerator.init(generatorParameters);

      LOG.debug("Generating DSA parameters");
      final DSAParameters parameters = parameterGenerator.generateParameters();

      // Wrap the parameters in an object which can be serialised. We convert the parameters into DHParameters for ease of use across algorithms.
      return new DHParametersWrapper(new DHParameters(parameters.getP(), parameters.getG(), parameters.getQ(), keyLengthN, keyLengthL));
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create DSA parameters", e);
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
    throw new CryptographyException("DSA algorithm cannot be used for encryption/decryption");
  }

  /**
   * Encrypts the plaintext data using the parameters and key pair. Only relevant if the algorithm can be used to encrypt/decrypt.
   *
   * @param random     Source of randomness.
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data to sign.
   * @return The ciphertext for the plaintext together with any other values.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public byte[][] encrypt(final SecureRandom random, final Parameters parameters, final KeyPair keyPair, final byte[] data) throws CryptographyException {
    throw new CryptographyException("DSA algorithm cannot be used for encryption/decryption");
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
    throw new CryptographyException("DSA algorithm cannot be used for non-interactive zero-knowledge proof of knowledge");
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
    // Make sure we have a private key.
    if (keyPair.getPrivateKey() == null) {
      throw new CryptographyException("Missing private key");
    }

    try {
      LOG.debug("DSA sign");

      // Convert the DH parameters.
      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final DSAParameters dsaParameters = new DSAParameters(dhParametersWrapper.getP(), dhParametersWrapper.getQ(), dhParametersWrapper.getG());
      final int hashLength = dsaParameters.getQ().bitLength();

      // Generate the signature.
      final DSADigestSigner signer = new DSADigestSigner(new DSASigner(), this.digestForLength(hashLength));
      final DSAPrivateKeyParameters privateKeyParameters = new DSAPrivateKeyParameters(keyPair.getPrivateKey(), dsaParameters);
      signer.init(true, privateKeyParameters);
      signer.update(data, 0, data.length);
      return signer.generateSignature();
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not DSA sign", e);
    }
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
    // Make sure we have a public key.
    if (keyPair.getPublicKey() == null) {
      throw new CryptographyException("Missing public key");
    }

    try {
      LOG.debug("DSA verify");

      // Convert the DH parameters.
      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final DSAParameters dsaParameters = new DSAParameters(dhParametersWrapper.getP(), dhParametersWrapper.getQ(), dhParametersWrapper.getG());
      final int hashLength = dsaParameters.getQ().bitLength();

      // Verify the signature.
      final DSADigestSigner signer = new DSADigestSigner(new DSASigner(), this.digestForLength(hashLength));
      final DSAPublicKeyParameters publicKeyParameters = new DSAPublicKeyParameters(keyPair.getPublicKey(), dsaParameters);
      signer.init(false, publicKeyParameters);
      signer.update(data, 0, data.length);
      return signer.verifySignature(signature);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not DSA sign", e);
    }
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
    throw new CryptographyException("DSA algorithm cannot be used for non-interactive zero-knowledge proof of knowledge");
  }
}
