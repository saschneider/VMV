/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import com.fasterxml.jackson.databind.MappingIterator;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.dataformat.csv.CsvGenerator;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
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
 * Statement tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class StatementTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testStatement() {
    final Statement statement = new Statement();
    assertThat(statement).isNotNull();

    final BigInteger leftHandSide = BigInteger.TEN;
    statement.setLeftHandSide(leftHandSide);
    assertThat(statement.getLeftHandSide()).isEqualTo(leftHandSide);

    final BigInteger rightHandSide = BigInteger.ONE;
    statement.setRightHandSide(rightHandSide);
    assertThat(statement.getRightHandSide()).isEqualTo(rightHandSide);
  }

  @Test
  public void testStatementSerialiseAll() throws Exception {
    final BigInteger leftHandSide = BigInteger.TEN;
    final BigInteger rightHandSide = BigInteger.ONE;
    final Statement statement = new Statement(leftHandSide, rightHandSide);
    assertThat(statement).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Statement.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(statement);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Statement.class).with(schema).readValues(csv);
    final Statement read = (Statement) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getLeftHandSide()).isEqualTo(leftHandSide);
    assertThat(read.getRightHandSide()).isEqualTo(rightHandSide);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testStatementSerialisePublic() throws Exception {
    final BigInteger leftHandSide = BigInteger.TEN;
    final BigInteger rightHandSide = BigInteger.ONE;
    final Statement statement = new Statement(leftHandSide, rightHandSide);
    assertThat(statement).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Statement.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(statement);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Statement.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final Statement read = (Statement) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getLeftHandSide()).isEqualTo(leftHandSide);
    assertThat(read.getRightHandSide()).isEqualTo(rightHandSide);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
