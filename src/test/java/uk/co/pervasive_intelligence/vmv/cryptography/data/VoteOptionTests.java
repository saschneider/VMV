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
 * Vote option tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VoteOptionTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testVoteOption() {
    final String option = "Test Vote";
    final VoteOption voteOption = new VoteOption(option);
    assertThat(voteOption).isNotNull();
    assertThat(voteOption.getOption()).isEqualTo(option);

    final String differentOption = "Another Vote";
    voteOption.setOption(differentOption);
    assertThat(voteOption.getOption()).isEqualTo(differentOption);

    final BigInteger optionNumberInGroup = BigInteger.TEN;
    voteOption.setOptionNumberInGroup(optionNumberInGroup);
    assertThat(voteOption.getOptionNumberInGroup()).isEqualTo(optionNumberInGroup);
  }

  @Test
  public void testVoteOptionSerialiseAll() throws Exception {
    final String option = "Test Vote";
    final BigInteger optionNumberInGroup = BigInteger.TEN;
    final VoteOption voteOption = new VoteOption(option);
    assertThat(voteOption).isNotNull();

    voteOption.setOptionNumberInGroup(optionNumberInGroup);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(VoteOption.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(voteOption);
    final MappingIterator<Object> iterator = csvMapper.readerFor(VoteOption.class).with(schema).readValues(csv);
    final VoteOption read = (VoteOption) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getOption()).isEqualTo(option);
    assertThat(read.getOptionNumberInGroup()).isEqualTo(optionNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoteOptionSerialiseERSImport() throws Exception {
    final String option = "Test Vote";
    final BigInteger optionNumberInGroup = BigInteger.TEN;
    final VoteOption voteOption = new VoteOption(option);
    assertThat(voteOption).isNotNull();

    voteOption.setOptionNumberInGroup(optionNumberInGroup);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(VoteOption.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSImport.class);
    final String csv = writer.writeValueAsString(voteOption);
    final MappingIterator<Object> iterator = csvMapper.readerFor(VoteOption.class).with(schema).withView(JacksonViews.ERSImport.class).readValues(csv);
    final VoteOption read = (VoteOption) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getOption()).isEqualTo(option);
    assertThat(read.getOptionNumberInGroup()).isEqualTo(optionNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoteOptionSerialisePublic() throws Exception {
    final String option = "Test Vote";
    final BigInteger optionNumberInGroup = BigInteger.TEN;
    final VoteOption voteOption = new VoteOption(option);
    assertThat(voteOption).isNotNull();

    voteOption.setOptionNumberInGroup(optionNumberInGroup);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(VoteOption.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(voteOption);
    final MappingIterator<Object> iterator = csvMapper.readerFor(VoteOption.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final VoteOption read = (VoteOption) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getOption()).isEqualTo(option);
    assertThat(read.getOptionNumberInGroup()).isEqualTo(optionNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
