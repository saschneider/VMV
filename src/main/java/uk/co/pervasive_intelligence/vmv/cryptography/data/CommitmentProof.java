/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.annotation.JsonUnwrapped;
import com.fasterxml.jackson.annotation.JsonView;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import javax.validation.constraints.NotNull;
import java.math.BigInteger;

/**
 * Encapsulates the non-interactive zero-knowledge proofs of knowledge of a commitment.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CommitmentProof {

  /** The A1' value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger a1Dash;

  /** The A2' value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger a2Dash;

  /** The B1' value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger b1Dash;

  /** The B2' value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger b2Dash;

  /** The C value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger c;

  /** The D value. */
  @JsonView(JacksonViews.Public.class)
  @NotNull
  private BigInteger d;

  /** The proof pi11. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi11")
  @NotNull
  private Proof pi11;

  /** The proof pi12. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi12")
  @NotNull
  private Proof pi12;

  /** The proof pi21. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi21")
  @NotNull
  private Proof pi21;

  /** The proof pi22. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi22")
  @NotNull
  private Proof pi22;

  /** The proof pi23. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi23")
  @NotNull
  private Proof pi23;

  /** The proof pi31. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi31")
  @NotNull
  private Proof pi31;

  /** The proof pi32. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi32")
  @NotNull
  private Proof pi32;

  /** The proof pi4. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi4")
  @NotNull
  private Proof pi4;

  /** The proof pi5. */
  @JsonView(JacksonViews.Public.class)
  @JsonUnwrapped(prefix = "pi5")
  @NotNull
  private Proof pi5;

  /**
   * Default constructor used for de-serialisation.
   */
  public CommitmentProof() {
    // Do nothing.
  }

  /**
   * Constructor requiring all fields.
   *
   * @param a1Dash The A1' value.
   * @param a2Dash The A2' value.
   * @param b1Dash The B1' value.
   * @param b2Dash The B2' value.
   * @param c      The C value.
   * @param d      The D value.
   * @param pi11   The proof pi11.
   * @param pi12   The proof pi12.
   * @param pi21   The proof pi21.
   * @param pi22   The proof pi22.
   * @param pi23   The proof pi23.
   * @param pi31   The proof pi31.
   * @param pi32   The proof pi32.
   * @param pi4    The proof pi4.
   * @param pi5    The proof pi5.
   */
  public CommitmentProof(final BigInteger a1Dash, final BigInteger a2Dash, final BigInteger b1Dash, final BigInteger b2Dash, final BigInteger c,
                         final BigInteger d, final Proof pi11, final Proof pi12, final Proof pi21, final Proof pi22, final Proof pi23, final Proof pi31,
                         final Proof pi32, final Proof pi4, final Proof pi5) {
    this.a1Dash = a1Dash;
    this.a2Dash = a2Dash;
    this.b1Dash = b1Dash;
    this.b2Dash = b2Dash;
    this.c = c;
    this.d = d;
    this.pi11 = pi11;
    this.pi12 = pi12;
    this.pi21 = pi21;
    this.pi22 = pi22;
    this.pi23 = pi23;
    this.pi31 = pi31;
    this.pi32 = pi32;
    this.pi4 = pi4;
    this.pi5 = pi5;
  }

  /**
   * @return The A1' value.
   */
  public BigInteger getA1Dash() {
    return this.a1Dash;
  }

  /**
   * @return The A2' value.
   */
  public BigInteger getA2Dash() {
    return this.a2Dash;
  }

  /**
   * @return The B1' value.
   */
  public BigInteger getB1Dash() {
    return this.b1Dash;
  }

  /**
   * @return The B2' value.
   */
  public BigInteger getB2Dash() {
    return this.b2Dash;
  }

  /**
   * @return The C value.
   */
  public BigInteger getC() {
    return this.c;
  }

  /**
   * @return The D value.
   */
  public BigInteger getD() {
    return this.d;
  }

  /**
   * @return The proof pi11.
   */
  public Proof getPi11() {
    return this.pi11;
  }

  /**
   * @return The proof pi12.
   */
  public Proof getPi12() {
    return this.pi12;
  }

  /**
   * @return The proof pi21.
   */
  public Proof getPi21() {
    return this.pi21;
  }

  /**
   * @return The proof pi22.
   */
  public Proof getPi22() {
    return this.pi22;
  }

  /**
   * @return The proof pi23.
   */
  public Proof getPi23() {
    return this.pi23;
  }

  /**
   * @return The proof pi31.
   */
  public Proof getPi31() {
    return this.pi31;
  }

  /**
   * @return The proof pi32.
   */
  public Proof getPi32() {
    return this.pi32;
  }

  /**
   * @return The proof pi4.
   */
  public Proof getPi4() {
    return this.pi4;
  }

  /**
   * @return The proof pi5.
   */
  public Proof getPi5() {
    return this.pi5;
  }
}
