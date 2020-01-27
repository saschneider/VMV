/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import com.beust.jcommander.IStringConverter;
import com.beust.jcommander.JCommander;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.shell.jcommander.JCommanderParameterResolverAutoConfiguration;

import java.io.File;
import java.math.BigInteger;

/**
 * JCommander configuration: used by Spring Shell to parse commands using {@link JCommander}. Based upon content of {@link
 * JCommanderParameterResolverAutoConfiguration}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@Configuration
@ConditionalOnClass(JCommander.class)
public class JCommanderConfiguration {

  /**
   * Creates the {@link JCommander} parameter resolver. We use a custom resolver to fix certain bugs with the default provided.
   *
   * @return The created parameter resolver.
   */
  @Bean
  @Order(1)
  public JCommanderParameterResolver parameterResolver() {
    return new JCommanderParameterResolver();
  }

  /**
   * Class used to parse string parameters into {@link BigInteger} objects.
   */
  public static class BigIntegerConverter implements IStringConverter<BigInteger> {

    /**
     * Converts the string value.
     *
     * @param value The value to convert.
     * @return The corresponding {@link File} value.
     */
    @Override
    public BigInteger convert(final String value) {
      return new BigInteger(value);
    }
  }

  /**
   * Class used to parse string parameters into {@link File} objects.
   */
  public static class FileConverter implements IStringConverter<File> {

    /**
     * Converts the string value.
     *
     * @param value The value to convert.
     * @return The corresponding {@link File} value.
     */
    @Override
    public File convert(final String value) {
      return new File(value);
    }
  }
}
