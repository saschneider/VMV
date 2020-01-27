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
 * Represents a possible vote option.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VoteOption {

  /** The option. */
  @JsonView({JacksonViews.ERSImport.class, JacksonViews.Public.class})
  private String option;

  /** The option as a member of the group. */
  @JsonView({JacksonViews.ERSImport.class, JacksonViews.Public.class})
  private BigInteger optionNumberInGroup;

  /**
   * Default constructor used for de-serialisation.
   */
  private VoteOption() {
    // Do nothing.
  }

  /**
   * Constructor allowing the option to be set.
   *
   * @param option The option.
   */
  public VoteOption(final String option) {
    this.option = option;
  }

  /**
   * @return The option.
   */
  public String getOption() {
    return this.option;
  }

  /**
   * Sets the option.
   *
   * @param option The option.
   */
  public void setOption(final String option) {
    this.option = option;
  }

  /**
   * @return The option as a member of the group.
   */
  public BigInteger getOptionNumberInGroup() {
    return this.optionNumberInGroup;
  }

  /**
   * Sets the option as a member of the group.
   *
   * @param optionNumberInGroup The option as a member of the group.
   */
  public void setOptionNumberInGroup(final BigInteger optionNumberInGroup) {
    this.optionNumberInGroup = optionNumberInGroup;
  }
}
