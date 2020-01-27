/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Encapsulates a Verificatum ciphertext element.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CipherText {

  /** The alpha component of the ciphertext. */
  private BigInteger alpha;

  /** The beta component of the ciphertext. */
  private BigInteger beta;

  /**
   * Constructor requiring the ciphertext elements.
   *
   * @param alpha The alpha component of the ciphertext.
   * @param beta  The beta component of the ciphertext.
   */
  public CipherText(final BigInteger alpha, final BigInteger beta) {
    this.alpha = alpha;
    this.beta = beta;
  }

  /**
   * Constructor for de-serialisation.
   */
  private CipherText() {
    // Do nothing.
  }

  /**
   * Constructor when encoded as bytes.
   *
   * @param values The bytes encoded using {@link #toByteArray()}.
   * @throws CryptographyException if the ciphertext could not be decoded.
   * @see #toByteArray()
   */
  public CipherText(final byte[] values) throws CryptographyException {
    try {
      // Decode the array as two length (int) and value pairs.
      final ByteArrayInputStream input = new ByteArrayInputStream(values);

      final byte[] alphaLengthBytes = new byte[Integer.BYTES];

      if (input.read(alphaLengthBytes) != Integer.BYTES) {
        throw new CryptographyException("Missing alpha length");
      }

      final int alphaLength = ByteBuffer.wrap(alphaLengthBytes).getInt();
      final byte[] alphaBytes = new byte[alphaLength];

      if (input.read(alphaBytes) != alphaLength) {
        throw new CryptographyException("Missing alpha");
      }

      final byte[] betaLengthBytes = new byte[Integer.BYTES];

      if (input.read(betaLengthBytes) != Integer.BYTES) {
        throw new CryptographyException("Missing beta length");
      }

      final int betaLength = ByteBuffer.wrap(betaLengthBytes).getInt();
      final byte[] betaBytes = new byte[betaLength];

      if (input.read(betaBytes) != betaLength) {
        throw new CryptographyException("Missing beta");
      }

      this.alpha = new BigInteger(1, alphaBytes);
      this.beta = new BigInteger(1, betaBytes);
    }
    catch (final CryptographyException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not decode ciphertext", e);
    }
  }

  /**
   * @return The alpha component of the ciphertext.
   */
  public BigInteger getAlpha() {
    return this.alpha;
  }

  /**
   * @return The beta component of the ciphertext.
   */
  public BigInteger getBeta() {
    return this.beta;
  }

  /**
   * Encodes the ciphertext into a byte array.
   *
   * @return The encoded byte array.
   * @throws CryptographyException if the ciphertext could not be encoded.
   */
  public byte[] toByteArray() throws CryptographyException {
    try {
      // Encode the array as two length (int) and value pairs.
      final byte[] alphaBytes = this.alpha.toByteArray();
      final byte[] betaBytes = this.beta.toByteArray();

      final ByteArrayOutputStream output = new ByteArrayOutputStream();
      output.write(ByteBuffer.allocate(Integer.BYTES).putInt(alphaBytes.length).array());
      output.write(alphaBytes);
      output.write(ByteBuffer.allocate(Integer.BYTES).putInt(betaBytes.length).array());
      output.write(betaBytes);

      return output.toByteArray();
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not encode ciphertext", e);
    }
  }
}
