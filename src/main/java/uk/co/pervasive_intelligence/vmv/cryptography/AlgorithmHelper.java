/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Proof;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Statement;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Defines an interface for a cryptographic algorithm helper.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public interface AlgorithmHelper {

  /** Default length L in bits. */
  int DEFAULT_LENGTH_L = 3072;

  /** Default length N in bits. */
  int DEFAULT_LENGTH_N = 256;

  /**
   * Default prime certainty in prime number generation. This will determine the number of times the Miller-Rabin test is performed against the probable prime up to
   * the limit defined in {@link BigInteger#isProbablePrime(int)}. We use a default to achieve up to 64 iterations, as recommended in: Albrecht, M., Paterson, K.,
   * Massimo, J., Somorovsky, J. (2018). Prime and Prejudice: Primality Testing Under Adversarial Conditions. 25th ACM Conference on Computer and Communications
   * Security 2018. 2018. p. 281-298.
   */
  int DEFAULT_PRIME_CERTAINTY = 128;

  /**
   * Uses the algorithm to create keys.
   *
   * @param random     Source of randomness.
   * @param parameters The created algorithm parameters.
   * @return The created keys.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  KeyPair createKeys(SecureRandom random, Parameters parameters) throws CryptographyException;

  /**
   * Creates parameters for the algorithm.
   *
   * @param random Source of randomness.
   * @param values Specific values of parameters to be used.
   * @return The corresponding algorithm parameters.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  Parameters createParameters(SecureRandom random, Object... values) throws CryptographyException;

  /**
   * Decrypts the ciphertext data using the parameters and key pair. Only relevant if the algorithm can be used to encrypt/decrypt.
   *
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data which has been encrypted.
   * @return The decrypted plaintext.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  byte[] decrypt(Parameters parameters, KeyPair keyPair, byte[] data) throws CryptographyException;

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
  byte[][] encrypt(SecureRandom random, Parameters parameters, KeyPair keyPair, byte[] data) throws CryptographyException;

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
  Proof generateProof(SecureRandom random, Parameters parameters, BigInteger witness, Statement... statements) throws CryptographyException;

  /**
   * @return The class used for the parameters.
   */
  Class<? extends Parameters> getParametersClass();

  /**
   * Signs the specified data using the parameters and key pair. Only relevant if the algorithm can be used to sign/verify.
   *
   * @param parameters The created algorithm parameters.
   * @param keyPair    The created algorithm key pair for the parameters.
   * @param data       The data to sign.
   * @return The signature for the data.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  byte[] sign(Parameters parameters, KeyPair keyPair, byte[] data) throws CryptographyException;

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
  boolean verify(Parameters parameters, KeyPair keyPair, byte[] data, byte[] signature) throws CryptographyException;

  /**
   * Verifies a non-interactive zero-knowledge proof of knowledge of one or more statements given their proof.
   *
   * @param parameters The created algorithm parameters.
   * @param proof      The proof of knowledge to verify.
   * @param statements The statements being proved.
   * @return True if the proof of knowledge is verified, false otherwise.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  boolean verifyProof(Parameters parameters, Proof proof, Statement... statements) throws CryptographyException;

}
