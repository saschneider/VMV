/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

/**
 * Defines cryptographic parameters.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public interface Parameters {

  /**
   * @return The name of the election.
   */
  String getName();

  /**
   * Sets the name of the election.
   *
   * @param name The name of the election.
   */
  void setName(String name);

  /**
   * @return The number of tellers.
   */
  int getNumberOfTellers();

  /**
   * Sets the number of tellers.
   *
   * @param numberOfTellers The number of tellers.
   */
  void setNumberOfTellers(int numberOfTellers);

  /**
   * @return The threshold number of tellers.
   */
  int getThresholdTellers();

  /**
   * Sets the number of tellers.
   *
   * @param thresholdTellers The threshold number of tellers.
   */
  void setThresholdTellers(int thresholdTellers);

}
