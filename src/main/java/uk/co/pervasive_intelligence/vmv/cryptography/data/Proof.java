/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import javax.validation.constraints.NotNull;
import java.math.BigInteger;

/**
 * Encapsulates a non-interactive zero-knowledge proof of knowledge.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class Proof {

  /** The hashed value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger hash;

  /** The signature value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger signature;

  /**
   * Default constructor used for de-serialisation.
   */
  public Proof() {
    // Do nothing.
  }

  /**
   * Constructor requiring all fields.
   *
   * @param hash      The hashed value.
   * @param signature The signature value.
   */
  public Proof(final BigInteger hash, final BigInteger signature) {
    this.hash = hash;
    this.signature = signature;
  }

  /**
   * @return The hashed value.
   */
  public BigInteger getHash() {
    return this.hash;
  }

  /**
   * Sets the hashed value.
   *
   * @param hash The hashed value.
   */
  public void setHash(final BigInteger hash) {
    this.hash = hash;
  }

  /**
   * @return The signature value.
   */
  public BigInteger getSignature() {
    return this.signature;
  }

  /**
   * Sets the signature value.
   *
   * @param signature The signature value.
   */
  public void setSignature(final BigInteger signature) {
    this.signature = signature;
  }
}
