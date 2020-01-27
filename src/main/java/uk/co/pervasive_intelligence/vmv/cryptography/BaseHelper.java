/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.util.DigestFactory;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Defines common methods for all cryptographic operations.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public abstract class BaseHelper {

  /**
   * Creates a digest for the required bit length. Works up to 512 bits.
   *
   * @param length The length in bits.
   * @return The created digest.
   */
  protected Digest digestForLength(final int length) {
    final Digest digest;

    if (length <= 160) {
      digest = DigestFactory.createSHA1();
    }
    else if (length <= 256) {
      digest = DigestFactory.createSHA256();
    }
    else if (length <= 384) {
      digest = DigestFactory.createSHA384();
    }
    else {
      digest = DigestFactory.createSHA512();
    }

    return digest;
  }

  /**
   * Generate a random number in the range 1 to limit-1.
   *
   * @param random The source of randomness.
   * @param limit  The exclusive limit to the generated random number.
   * @return A random number in the range 1 to limit-1.
   */
  public BigInteger generateRandom(final SecureRandom random, final BigInteger limit) {
    final int limitBitLength = limit.bitLength();
    BigInteger value = new BigInteger(limitBitLength, random);

    while (value.equals(BigInteger.ZERO) || (value.compareTo(limit.subtract(BigInteger.valueOf(2))) > 0)) {
      value = new BigInteger(limitBitLength, random);
    }

    return value;
  }

  /**
   * Calculates the hash of the specified {@link BigInteger} values and returns the corresponding {@link BigInteger}. A hash for the specified bit length is used.
   *
   * @param bitLength The digest bit length to use to hash the data.
   * @param values    The values to add to the digest to create the hash.
   * @return The hash value as a {@link BigInteger}.
   */
  protected BigInteger hash(final int bitLength, final BigInteger... values) {
    final Digest digest = this.digestForLength(bitLength);

    for (final BigInteger value : values) {
      final byte[] bytes = value.toByteArray();
      digest.update(bytes, 0, bytes.length);
    }

    final byte[] output = new byte[digest.getDigestSize()];
    digest.doFinal(output, 0);

    return new BigInteger(1, output);
  }
}
