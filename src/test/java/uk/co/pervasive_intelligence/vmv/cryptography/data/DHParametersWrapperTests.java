/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.dataformat.csv.CsvGenerator;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.bouncycastle.crypto.params.DHParameters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseShellComponent;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.JacksonViews;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.math.BigInteger;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DH parameters wrapper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class DHParametersWrapperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testDHParametersWrapperFromParameters() {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    assertThat(wrapper).isNotNull();
    assertThat(wrapper.getParameters()).isEqualTo(object);
    assertThat(wrapper.getG()).isEqualTo(object.getG());
    assertThat(wrapper.getP()).isEqualTo(object.getP());
    assertThat(wrapper.getQ()).isEqualTo(object.getQ());
    assertThat(wrapper.getM()).isEqualTo(object.getM());
    assertThat(wrapper.getL()).isEqualTo(object.getL());
    assertThat(wrapper.getJ()).isEqualTo(object.getJ());
  }

  @Test
  public void testDHParametersWrapperFromValues() {
    final DHParametersWrapper wrapper = new DHParametersWrapper(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE);
    assertThat(wrapper).isNotNull();
    assertThat(wrapper.getParameters()).isNotNull();
    assertThat(wrapper.getG()).isEqualTo(BigInteger.TEN);
    assertThat(wrapper.getP()).isEqualTo(BigInteger.TEN);
    assertThat(wrapper.getQ()).isEqualTo(BigInteger.ZERO);
    assertThat(wrapper.getM()).isEqualTo(1);
    assertThat(wrapper.getL()).isEqualTo(2);
    assertThat(wrapper.getJ()).isEqualTo(BigInteger.ONE);
  }

  @Test
  public void testDHParametersWrapperSerialiseAll() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    assertThat(wrapper).isNotNull();

    final String name = "Election";
    final int numberOfTellers = 4;
    final int thresholdTellers = 3;
    wrapper.setName(name);
    wrapper.setNumberOfTellers(numberOfTellers);
    wrapper.setThresholdTellers(thresholdTellers);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(DHParametersWrapper.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(wrapper);
    final MappingIterator<Object> iterator = csvMapper.readerFor(DHParametersWrapper.class).with(schema).readValues(csv);
    final DHParametersWrapper read = (DHParametersWrapper) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getParameters()).isEqualTo(object);
    assertThat(read.getG()).isEqualTo(object.getG());
    assertThat(read.getP()).isEqualTo(object.getP());
    assertThat(read.getQ()).isEqualTo(object.getQ());
    assertThat(read.getM()).isEqualTo(object.getM());
    assertThat(read.getL()).isEqualTo(object.getL());
    assertThat(read.getJ()).isEqualTo(object.getJ());
    assertThat(wrapper.getName()).isEqualTo(name);
    assertThat(wrapper.getNumberOfTellers()).isEqualTo(numberOfTellers);
    assertThat(wrapper.getThresholdTellers()).isEqualTo(thresholdTellers);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testDHParametersWrapperSerialisePublic() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    assertThat(wrapper).isNotNull();

    final String name = "Election";
    final int numberOfTellers = 4;
    final int thresholdTellers = 3;
    wrapper.setName(name);
    wrapper.setNumberOfTellers(numberOfTellers);
    wrapper.setThresholdTellers(thresholdTellers);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(DHParametersWrapper.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(wrapper);
    final MappingIterator<Object> iterator = csvMapper.readerFor(DHParametersWrapper.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final DHParametersWrapper read = (DHParametersWrapper) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getParameters()).isEqualTo(object);
    assertThat(read.getG()).isEqualTo(object.getG());
    assertThat(read.getP()).isEqualTo(object.getP());
    assertThat(read.getQ()).isEqualTo(object.getQ());
    assertThat(read.getM()).isEqualTo(object.getM());
    assertThat(read.getL()).isEqualTo(object.getL());
    assertThat(read.getJ()).isEqualTo(object.getJ());
    assertThat(wrapper.getName()).isEqualTo(name);
    assertThat(wrapper.getNumberOfTellers()).isEqualTo(numberOfTellers);
    assertThat(wrapper.getThresholdTellers()).isEqualTo(thresholdTellers);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
