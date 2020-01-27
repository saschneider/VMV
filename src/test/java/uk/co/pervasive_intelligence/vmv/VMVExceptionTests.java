/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * VMV exception tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VMVExceptionTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testMessage() {
    final String message = "Test";
    final VMVException exception = new VMVException(message);

    assertThat(exception.getMessage()).isEqualTo(message);
  }

  @Test
  public void testMessageCause() {
    final String message = "Test";
    final Throwable cause = new IllegalArgumentException();
    final VMVException exception = new VMVException(message, cause);

    assertThat(exception.getMessage()).isEqualTo(message);
    assertThat(exception.getCause()).isEqualTo(cause);
  }
}
