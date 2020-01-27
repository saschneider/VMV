/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import javax.validation.constraints.NotNull;
import java.math.BigInteger;

/**
 * Defines a private and public key pair.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class KeyPair {

  /** The private key. */
  @JsonView(JacksonViews.Private.class)
  private BigInteger privateKey;

  /** The public key. */
  @JsonView({JacksonViews.ERSKeyImport.class, JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteImport.class, JacksonViews.Vote.class,
      JacksonViews.VoterVote.class, JacksonViews.Public.class})
  @NotNull
  private BigInteger publicKey;

  /**
   * Constructor for de-serialisation.
   */
  private KeyPair() {
    // Do nothing.
  }

  /**
   * Constructor.
   *
   * @param privateKey The private key.
   * @param publicKey  The public key.
   */
  public KeyPair(final BigInteger privateKey, final BigInteger publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /**
   * @return The private key.
   */
  public BigInteger getPrivateKey() {
    return this.privateKey;
  }

  /**
   * @return The public key.
   */
  public BigInteger getPublicKey() {
    return this.publicKey;
  }
}
