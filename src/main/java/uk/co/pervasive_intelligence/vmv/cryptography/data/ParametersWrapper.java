/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.validation.constraints.Min;
import javax.validation.constraints.NotNull;

/**
 * An abstract {@link Parameters} wrapper class. Override to provide specific parameters for serialisation.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public abstract class ParametersWrapper implements Parameters {

  /** The parameters being wrapped. */
  @JsonIgnore
  private final Object parameters;

  /** The name of the election. */
  @NotNull
  private String name;

  /** The number of tellers. */
  @Min(0)
  private int numberOfTellers;

  /** The threshold number of tellers. */
  @Min(0)
  private int thresholdTellers;

  /**
   * Wrapping constructor.
   *
   * @param parameters The parameters being wrapped.
   */
  public ParametersWrapper(final Object parameters) {
    this.parameters = parameters;
  }

  /**
   * @return The name of the election.
   */
  @Override
  public String getName() {
    return this.name;
  }

  /**
   * Sets the name of the election.
   *
   * @param name The name of the election.
   */
  @Override
  public void setName(final String name) {
    this.name = name;
  }

  /**
   * @return The number of tellers.
   */
  @Override
  public int getNumberOfTellers() {
    return this.numberOfTellers;
  }

  /**
   * Sets the number of tellers.
   *
   * @param numberOfTellers The number of tellers.
   */
  @Override
  public void setNumberOfTellers(final int numberOfTellers) {
    this.numberOfTellers = numberOfTellers;
  }

  /**
   * @return The parameters being wrapped.
   */
  public Object getParameters() {
    return this.parameters;
  }

  /**
   * @return The threshold number of tellers.
   */
  @Override
  public int getThresholdTellers() {
    return this.thresholdTellers;
  }

  /**
   * Sets the number of tellers.
   *
   * @param thresholdTellers The threshold number of tellers.
   */
  @Override
  public void setThresholdTellers(final int thresholdTellers) {
    this.thresholdTellers = thresholdTellers;
  }
}
