/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cryptography exception tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CryptographyExceptionTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testMessage() {
    final String message = "Test";
    final CryptographyException exception = new CryptographyException(message);

    assertThat(exception.getMessage()).isEqualTo(message);
  }

  @Test
  public void testMessageCause() {
    final String message = "Test";
    final Throwable cause = new IllegalArgumentException();
    final CryptographyException exception = new CryptographyException(message, cause);

    assertThat(exception.getMessage()).isEqualTo(message);
    assertThat(exception.getCause()).isEqualTo(cause);
  }
}
