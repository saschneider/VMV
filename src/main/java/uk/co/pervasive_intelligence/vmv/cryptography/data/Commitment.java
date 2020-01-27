/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import java.math.BigInteger;

/**
 * Represents commitment values for the association between voter key pairs and tracker numbers.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class Commitment {

  /** The encrypted g value. */
  @JsonView(JacksonViews.Public.class)
  private byte[] encryptedG;

  /** The encrypted h value. */
  @JsonView(JacksonViews.Public.class)
  private byte[] encryptedH;

  /** The g value. */
  @JsonView(JacksonViews.Private.class)
  private BigInteger g;

  /** The h value. */
  @JsonView(JacksonViews.Private.class)
  private BigInteger h;

  /** The associated public key. */
  @JsonView(JacksonViews.Public.class)
  private BigInteger publicKey;

  /**
   * Default constructor used for de-serialisation.
   */
  public Commitment() {
    // Do nothing.
  }

  /**
   * @return The encrypted g value.
   */
  public byte[] getEncryptedG() {
    return this.encryptedG;
  }

  /**
   * Sets the encrypted g value.
   *
   * @param encryptedG The encrypted g value.
   */
  public void setEncryptedG(final byte[] encryptedG) {
    this.encryptedG = encryptedG;
  }

  /**
   * @return The encrypted h value.
   */
  public byte[] getEncryptedH() {
    return this.encryptedH;
  }

  /**
   * Sets the encrypted h value.
   *
   * @param encryptedH The encrypted h value.
   */
  public void setEncryptedH(final byte[] encryptedH) {
    this.encryptedH = encryptedH;
  }

  /**
   * @return The g value.
   */
  public BigInteger getG() {
    return this.g;
  }

  /**
   * Sets the g value.
   *
   * @param g The g value.
   */
  public void setG(final BigInteger g) {
    this.g = g;
  }

  /**
   * @return The h value.
   */
  public BigInteger getH() {
    return this.h;
  }

  /**
   * Sets the h value.
   *
   * @param h The h value.
   */
  public void setH(final BigInteger h) {
    this.h = h;
  }

  /**
   * @return The associated public key.
   */
  public BigInteger getPublicKey() {
    return this.publicKey;
  }

  /**
   * Sets the associated public key.
   *
   * @param publicKey The associated public key.
   */
  public void setPublicKey(final BigInteger publicKey) {
    this.publicKey = publicKey;
  }
}
