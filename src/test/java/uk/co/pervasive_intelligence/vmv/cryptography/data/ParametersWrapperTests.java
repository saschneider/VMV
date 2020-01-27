/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parameters wrapper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ParametersWrapperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testParametersWrapper() {
    final Object object = new Object();
    final ParametersWrapper wrapper = new TestParametersWrapper(object);
    assertThat(wrapper).isNotNull();
    assertThat(wrapper.getParameters()).isEqualTo(object);

    final String name = "Election";
    final int numberOfTellers = 4;
    final int thresholdTellers = 3;

    wrapper.setName(name);
    assertThat(wrapper.getName()).isEqualTo(name);

    wrapper.setNumberOfTellers(numberOfTellers);
    assertThat(wrapper.getNumberOfTellers()).isEqualTo(numberOfTellers);

    wrapper.setThresholdTellers(thresholdTellers);
    assertThat(wrapper.getThresholdTellers()).isEqualTo(thresholdTellers);
  }

  /**
   * Parameters wrapper implementation.
   */
  public static class TestParametersWrapper extends ParametersWrapper {

    public TestParametersWrapper(final Object parameters) {
      super(parameters);
    }
  }
}
