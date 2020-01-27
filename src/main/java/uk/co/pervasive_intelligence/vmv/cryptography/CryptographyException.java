/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

/**
 * Exception thrown by the {@link CryptographyHelper}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CryptographyException extends Exception {

  /** Serial version UID. */
  private static final long serialVersionUID = 596184523465397638L;

  /**
   * Constructs a new exception with the specified detail message. The cause is not initialised, and may subsequently be initialised by a call to {@link
   * #initCause}.
   *
   * @param message The detail message. The detail message is saved for later retrieval by the {@link #getMessage()} method.
   */
  public CryptographyException(final String message) {
    super(message);
  }

  /**
   * Constructs a new exception with the specified detail message and cause.  <p>Note that the detail message associated with {@code cause} is <i>not</i>
   * automatically incorporated in this exception's detail message.
   *
   * @param message The detail message (which is saved for later retrieval by the {@link #getMessage()} method).
   * @param cause   The cause (which is saved for later retrieval by the {@link #getCause()} method).  (A <tt>null</tt> value is permitted, and indicates that the
   *                cause is nonexistent or unknown.)
   */
  public CryptographyException(final String message, final Throwable cause) {
    super(message, cause);
  }

}
