/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import java.math.BigInteger;
import java.nio.ByteBuffer;

/**
 * Represents a tracker number.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class TrackerNumber {

  /** The encrypted tracker number as a member of the group. */
  @JsonView({JacksonViews.ERSVoteEncryptedImport.class, JacksonViews.ERSVoteImport.class, JacksonViews.Vote.class, JacksonViews.Public.class})
  private byte[] encryptedTrackerNumberInGroup;

  /** The plaintext tracker number: an object to allow for null values. */
  @JsonView({JacksonViews.RestrictedPublic.class, JacksonViews.Mixed.class})
  private Integer trackerNumber;

  /** The plaintext tracker number as a member of the group. */
  @JsonView(JacksonViews.RestrictedPublic.class)
  private BigInteger trackerNumberInGroup;

  /**
   * Constructor for de-serialisation.
   */
  private TrackerNumber() {
    // Do nothing.
  }

  /**
   * Constructor requiring the mandatory fields.
   *
   * @param trackerNumber                 The tracker number.
   * @param trackerNumberInGroup          The plaintext tracker number as a member of the group.
   * @param encryptedTrackerNumberInGroup The encrypted tracker number as a member of the group.
   */
  public TrackerNumber(final Integer trackerNumber, final BigInteger trackerNumberInGroup, final byte[] encryptedTrackerNumberInGroup) {
    this.trackerNumber = trackerNumber;
    this.trackerNumberInGroup = trackerNumberInGroup;
    this.encryptedTrackerNumberInGroup = encryptedTrackerNumberInGroup;
  }

  /**
   * Indicates whether some other object is "equal to" this one.
   *
   * @param object the reference object with which to compare.
   * @return {@code true} if this object is the same as the obj argument; {@code false} otherwise.
   * @see #hashCode()
   */
  @Override
  public boolean equals(final Object object) {
    if (this == object) {
      return true;
    }

    if (object == null || (this.getClass() != object.getClass())) {
      return false;
    }

    final TrackerNumber that = (TrackerNumber) object;
    return this.trackerNumber.equals(that.trackerNumber);
  }

  /**
   * @return A byte representation of the tracker number.
   */
  @JsonIgnore
  public byte[] getBytes() {
    return ByteBuffer.allocate(Integer.BYTES).putInt(this.trackerNumber).array();
  }

  /**
   * @return The voter's encrypted tracker number as a member of the group.
   */
  public byte[] getEncryptedTrackerNumberInGroup() {
    return this.encryptedTrackerNumberInGroup;
  }

  /**
   * @return The tracker number.
   */
  public Integer getTrackerNumber() {
    return this.trackerNumber;
  }

  /**
   * @return The voter's plaintext tracker number as a member of the group.
   */
  public BigInteger getTrackerNumberInGroup() {
    return this.trackerNumberInGroup;
  }

  /**
   * @return The hash code for the tracker number.
   * @see #equals(Object)
   */
  @Override
  public int hashCode() {
    return this.trackerNumber.hashCode();
  }
}
