/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import java.math.BigInteger;

/**
 * Encapsulates the voter data.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class Voter {

  /** The voter's tracker number commitment alpha. */
  @JsonView({JacksonViews.ERSVoteExport.class})
  private BigInteger alpha;

  /** The voter's tracker number commitment beta. */
  @JsonView({JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteImport.class, JacksonViews.Vote.class, JacksonViews.Public.class})
  private BigInteger beta;

  /** The voter's encrypted vote. */
  @JsonView({JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteExport.class, JacksonViews.Vote.class, JacksonViews.VoterVote.class})
  private byte[] encryptedVote;

  /** The voter's encrypted vote signature. */
  @JsonView({JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteExport.class, JacksonViews.Vote.class, JacksonViews.VoterVote.class})
  private byte[] encryptedVoteSignature;

  /** The voter's unique identifier: an object to allow for null values. */
  @JsonView({JacksonViews.ERSExport.class, JacksonViews.ERSVoteExport.class, JacksonViews.ERSImport.class, JacksonViews.ERSKeyImport.class,
      JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteImport.class})
  private Long id;

  /** The voter's plaintext vote. */
  @JsonView({JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteImport.class, JacksonViews.Mixed.class})
  private String plainTextVote;

  /** The voter's encrypted tracker number. */
  @JsonUnwrapped
  private TrackerNumber trackerNumber;

  /** The voter's key pairs. */
  @JsonUnwrapped
  private VoterKeyPairs voterKeyPairs;

  /**
   * Default constructor used for de-serialisation and when there is no voter identifier.
   */
  public Voter() {
    // Do nothing.
  }

  /**
   * Constructor allow the fields to be set.
   *
   * @param id The voter's unique identifier.
   */
  public Voter(final long id) {
    this.id = id;
  }

  /**
   * @return The voter's tracker number commitment alpha.
   */
  public BigInteger getAlpha() {
    return this.alpha;
  }

  /**
   * Sets the voter's tracker number commitment alpha.
   *
   * @param alpha The voter's tracker number commitment alpha.
   */
  public void setAlpha(final BigInteger alpha) {
    this.alpha = alpha;
  }

  /**
   * @return The voter's tracker number commitment beta.
   */
  public BigInteger getBeta() {
    return this.beta;
  }

  /**
   * Sets the voter's tracker number commitment beta.
   *
   * @param beta The voter's tracker number commitment beta.
   */
  public void setBeta(final BigInteger beta) {
    this.beta = beta;
  }

  /**
   * @return The voter's encrypted vote.
   */
  public byte[] getEncryptedVote() {
    return this.encryptedVote;
  }

  /**
   * Sets the voter's encrypted vote.
   *
   * @param encryptedVote The voter's encrypted vote.
   */
  public void setEncryptedVote(final byte[] encryptedVote) {
    this.encryptedVote = encryptedVote;
  }

  /**
   * @return The voter's encrypted vote signature.
   */
  public byte[] getEncryptedVoteSignature() {
    return this.encryptedVoteSignature;
  }

  /**
   * Sets the voter's encrypted vote signature.
   *
   * @param encryptedVoteSignature The voter's encrypted vote signature.
   */
  public void setEncryptedVoteSignature(final byte[] encryptedVoteSignature) {
    this.encryptedVoteSignature = encryptedVoteSignature;
  }

  /**
   * @return The voter's unique identifier.
   */
  public Long getId() {
    return this.id;
  }

  /**
   * Sets the voter's unique identifier.
   *
   * @param id The voter's unique identifier
   */
  public void setId(final Long id) {
    this.id = id;
  }

  /**
   * @return The voter's plaintext vote.
   */
  public String getPlainTextVote() {
    return this.plainTextVote;
  }

  /**
   * Sets the voter's plaintext vote.
   *
   * @param plainTextVote The voter's plaintext vote.
   */
  public void setPlainTextVote(final String plainTextVote) {
    this.plainTextVote = plainTextVote;
  }

  /**
   * @return The voter's plaintext tracker number.
   */
  public TrackerNumber getTrackerNumber() {
    return this.trackerNumber;
  }

  /**
   * Sets the voter's encrypted tracker number.
   *
   * @param trackerNumber The voter's encrypted tracker number.
   */
  public void setTrackerNumber(final TrackerNumber trackerNumber) {
    this.trackerNumber = trackerNumber;
  }

  /**
   * @return The voter's key pairs.
   */
  public VoterKeyPairs getVoterKeyPairs() {
    return this.voterKeyPairs;
  }

  /**
   * Sets the voter's key pairs.
   *
   * @param voterKeyPairs The voter's key pairs.
   */
  public void setVoterKeyPairs(final VoterKeyPairs voterKeyPairs) {
    this.voterKeyPairs = voterKeyPairs;
  }
}
