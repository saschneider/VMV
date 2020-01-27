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
 * Shell progress tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ShellProgressTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testClear() {
    final ShellProgress shellProgress = new ShellProgress();
    assertThat(shellProgress).isNotNull();

    shellProgress.onStart("name");
    shellProgress.onProgress(23f);
    shellProgress.onEnd();
  }
}
