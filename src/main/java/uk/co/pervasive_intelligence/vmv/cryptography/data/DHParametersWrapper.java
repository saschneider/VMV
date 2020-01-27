/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import org.bouncycastle.crypto.params.DHParameters;

import java.math.BigInteger;

/**
 * {@link Parameters} wrapper class for {@link DHParameters}.
 */
public class DHParametersWrapper extends ParametersWrapper {

  /**
   * Wrapping constructor.
   *
   * @param parameters The parameters being wrapped.
   */
  public DHParametersWrapper(final Object parameters) {
    super(parameters);
  }

  /**
   * Constructor for de-serialisation.
   *
   * @param g The g parameter.
   * @param p The p parameter.
   * @param q The q parameter.
   * @param m The m parameter.
   * @param l The l parameter.
   * @param j The j parameter.
   */
  @JsonCreator
  public DHParametersWrapper(@JsonProperty("g") final BigInteger g, @JsonProperty("p") final BigInteger p, @JsonProperty("q") final BigInteger q,
                             @JsonProperty("m") final int m, @JsonProperty("l") final int l, @JsonProperty("j") final BigInteger j) {
    this(new DHParameters(p, g, q, m, l, j, null));
  }

  /**
   * @return The g parameter.
   */
  public BigInteger getG() {
    return ((DHParameters) this.getParameters()).getG();
  }

  /**
   * @return The j parameter.
   */
  public BigInteger getJ() {
    return ((DHParameters) this.getParameters()).getJ();
  }

  /**
   * @return The l parameter.
   */
  public int getL() {
    return ((DHParameters) this.getParameters()).getL();
  }

  /**
   * @return The m parameter.
   */
  public int getM() {
    return ((DHParameters) this.getParameters()).getM();
  }

  /**
   * @return The p parameter.
   */
  public BigInteger getP() {
    return ((DHParameters) this.getParameters()).getP();
  }

  /**
   * @return The q parameter.
   */
  public BigInteger getQ() {
    return ((DHParameters) this.getParameters()).getQ();
  }
}
