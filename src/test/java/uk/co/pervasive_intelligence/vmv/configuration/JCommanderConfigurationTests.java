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
import org.springframework.shell.ParameterResolver;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JCommander configuration tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class JCommanderConfigurationTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testFileConverter() {
    final JCommanderConfiguration.FileConverter fileConverter = new JCommanderConfiguration.FileConverter();
    assertThat(fileConverter).isNotNull();

    final String path = "test.txt";
    assertThat(fileConverter.convert(path)).isEqualTo(new File(path));
  }

  @Test
  public void testParameterResolver() {
    final JCommanderConfiguration configuration = new JCommanderConfiguration();
    assertThat(configuration).isNotNull();
    assertThat(configuration.parameterResolver()).isInstanceOf(ParameterResolver.class);
  }
}
