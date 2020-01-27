/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JCommander parameter resolver tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class JCommanderParameterResolverTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testJCommanderParameterResolver() {
    // Test the we can create the object only as the class is otherwise copied from the Spring source.
    final JCommanderParameterResolver resolver = new JCommanderParameterResolver();
    assertThat(resolver).isNotNull();
  }
}
