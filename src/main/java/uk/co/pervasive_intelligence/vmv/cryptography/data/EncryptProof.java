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
 * Encapsulates the non-interactive zero-knowledge proofs of knowledge of an ElGamal encryption.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class EncryptProof {

  /** The c1Bar value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger c1Bar;

  /** The c1R value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger c1R;

  /** The c2Bar value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger c2Bar;

  /** The c2R value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger c2R;

  /** The voter's encrypted vote signature. */
  @JsonView(JacksonViews.Public.class)
  private byte[] encryptedVoteSignature;

  /**
   * Default constructor used for de-serialisation.
   */
  public EncryptProof() {
    // Do nothing.
  }

  /**
   * Constructor requiring all fields.
   *
   * @param c1R                    The c1R value.
   * @param c2R                    The c2R value.
   * @param c1Bar                  The c1Bar value.
   * @param c2Bar                  The c2Bar value.
   * @param encryptedVoteSignature The voter's encrypted vote signature.
   */
  public EncryptProof(final BigInteger c1R, final BigInteger c2R, final BigInteger c1Bar, final BigInteger c2Bar, final byte[] encryptedVoteSignature) {
    this.c1R = c1R;
    this.c2R = c2R;
    this.c1Bar = c1Bar;
    this.c2Bar = c2Bar;
    this.encryptedVoteSignature = encryptedVoteSignature;
  }

  /**
   * @return The c1Bar value.
   */
  public BigInteger getC1Bar() {
    return this.c1Bar;
  }

  /**
   * @return The c1R value.
   */
  public BigInteger getC1R() {
    return this.c1R;
  }

  /**
   * @return The c2Bar value.
   */
  public BigInteger getC2Bar() {
    return this.c2Bar;
  }

  /**
   * @return The c2R value.
   */
  public BigInteger getC2R() {
    return this.c2R;
  }

  /**
   * @return The voter's encrypted vote signature.
   */
  public byte[] getEncryptedVoteSignature() {
    return this.encryptedVoteSignature;
  }
}
