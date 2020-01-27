/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonUnwrapped;

import javax.validation.constraints.NotNull;

/**
 * Defines the voter's key pairs.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VoterKeyPairs {

  /** The signature key pair. */
  @JsonUnwrapped(suffix = "Signature")
  @NotNull
  private KeyPair signatureKeyPair;

  /** The trapdoor key pair. */
  @JsonUnwrapped(suffix = "Trapdoor")
  @NotNull
  private KeyPair trapdoorKeyPair;

  /**
   * Constructor requiring the key pairs.
   *
   * @param trapdoorKeyPair  The trapdoor key pair.
   * @param signatureKeyPair The signature key pair.
   */
  public VoterKeyPairs(final KeyPair trapdoorKeyPair, final KeyPair signatureKeyPair) {
    this.trapdoorKeyPair = trapdoorKeyPair;
    this.signatureKeyPair = signatureKeyPair;
  }

  /**
   * Constructor for de-serialisation.
   */
  private VoterKeyPairs() {
    // Do nothing.
  }

  /**
   * @return The signature key pair.
   */
  public KeyPair getSignatureKeyPair() {
    return this.signatureKeyPair;
  }

  /**
   * @return The trapdoor key pair.
   */
  public KeyPair getTrapdoorKeyPair() {
    return this.trapdoorKeyPair;
  }
}
