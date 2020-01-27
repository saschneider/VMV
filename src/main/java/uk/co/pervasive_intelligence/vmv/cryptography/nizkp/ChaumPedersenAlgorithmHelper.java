/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.nizkp;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.pervasive_intelligence.vmv.cryptography.AlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.BaseHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

/**
 * Chaum-Pedersen NIZKP implementation of the {@link AlgorithmHelper}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ChaumPedersenAlgorithmHelper extends BaseHelper implements AlgorithmHelper {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ChaumPedersenAlgorithmHelper.class);

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
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used to create keys");
  }

  /**
   * Creates parameters for the algorithm.
   *
   * @param random Source of randomness.
   * @param values Specific values of parameters to be used.
   * @return The corresponding algorithm parameters.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public Parameters createParameters(final SecureRandom random, final Object... values) throws CryptographyException {
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used to create parameters");
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
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used for encryption/decryption");
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
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used for encryption/decryption");
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
    // Make sure we have a witness and one or more statements.
    if (witness == null) {
      throw new CryptographyException("Missing witness");
    }

    if ((statements == null) || (statements.length < 1)) {
      throw new CryptographyException("Must have at least one statement");
    }

    try {
      LOG.debug("Generate proof");

      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final BigInteger p = dhParametersWrapper.getP();
      final BigInteger q = dhParametersWrapper.getQ();

      // Generate a random number in the range 1 to q-1.
      final BigInteger k = this.generateRandom(random, q);

      // Calculate t_n = statement_n(rhs)^k mod p.
      final List<BigInteger> tn = new ArrayList<>();

      for (final Statement statement : statements) {
        tn.add(statement.getRightHandSide().modPow(k, p));
      }

      // Calculate c = H(t_1, ... , statement_1(rhs), statement_1(lhs), ... , p, q).
      final List<BigInteger> values = new ArrayList<>(tn);
      for (final Statement statement : statements) {
        values.add(statement.getRightHandSide());
        values.add(statement.getLeftHandSide());
      }
      values.add(p);
      values.add(q);
      final BigInteger c = this.hash(q.bitLength(), values.toArray(new BigInteger[0]));

      // Calculate r = k + cx mod q.
      final BigInteger r = k.add(c.multiply(witness)).mod(q);

      return new Proof(c, r);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not generate proof", e);
    }
  }

  /**
   * @return The class used for the parameters.
   */
  @Override
  public Class<? extends Parameters> getParametersClass() {
    return null;
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
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used for sign/verify");
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
    throw new CryptographyException("Chaum-Pedersen algorithm cannot be used for sign/verify");
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
    // Make sure we have one or more statements and a proof.
    if (proof == null) {
      throw new CryptographyException("Missing proof");
    }

    if ((statements == null) || (statements.length < 1)) {
      throw new CryptographyException("Must have at least one statement");
    }

    try {
      LOG.debug("Verify proof");

      final DHParametersWrapper dhParametersWrapper = (DHParametersWrapper) parameters;
      final BigInteger p = dhParametersWrapper.getP();
      final BigInteger q = dhParametersWrapper.getQ();

      // Calculate t_n = statement_n(rhs)^proof(signature) * statement_n(lhs)^-proof(hash) mod p.
      final List<BigInteger> tn = new ArrayList<>();

      for (final Statement statement : statements) {
        final BigInteger first = statement.getRightHandSide().modPow(proof.getSignature(), p);
        final BigInteger second = statement.getLeftHandSide().modPow(proof.getHash().negate(), p);
        tn.add(first.multiply(second).mod(p));
      }

      // Calculate c = H(t_1, ... , statement_1(rhs), statement_1(lhs), ... , p, q).
      final List<BigInteger> values = new ArrayList<>(tn);
      for (final Statement statement : statements) {
        values.add(statement.getRightHandSide());
        values.add(statement.getLeftHandSide());
      }
      values.add(p);
      values.add(q);
      final BigInteger c = this.hash(q.bitLength(), values.toArray(new BigInteger[0]));

      return proof.getHash().equals(c);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not verify proof", e);
    }
  }
}
