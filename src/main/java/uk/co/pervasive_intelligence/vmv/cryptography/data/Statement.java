/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import java.math.BigInteger;

/**
 * Encapsulates a statement for a non-interactive zero-knowledge proof of knowledge.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class Statement {

  /** The left hand side value. */
  @JsonView(JacksonViews.Public.class)
  private BigInteger leftHandSide;

  /** The right hand side value. */
  @JsonView(JacksonViews.Public.class)
  private BigInteger rightHandSide;

  /**
   * Default constructor used for de-serialisation.
   */
  public Statement() {
    // Do nothing.
  }

  /**
   * Constructor requiring all fields.
   *
   * @param leftHandSide  The left hand side value.
   * @param rightHandSide The right hand side value.
   */
  public Statement(final BigInteger leftHandSide, final BigInteger rightHandSide) {
    this.leftHandSide = leftHandSide;
    this.rightHandSide = rightHandSide;
  }

  /**
   * @return The left hand side value.
   */
  public BigInteger getLeftHandSide() {
    return this.leftHandSide;
  }

  /**
   * Sets the left hand side value.
   *
   * @param leftHandSide The left hand side value.
   */
  public void setLeftHandSide(final BigInteger leftHandSide) {
    this.leftHandSide = leftHandSide;
  }

  /**
   * @return The right hand side value.
   */
  public BigInteger getRightHandSide() {
    return this.rightHandSide;
  }

  /**
   * Sets the right hand side value.
   *
   * @param rightHandSide The right hand side value.
   */
  public void setRightHandSide(final BigInteger rightHandSide) {
    this.rightHandSide = rightHandSide;
  }
}
