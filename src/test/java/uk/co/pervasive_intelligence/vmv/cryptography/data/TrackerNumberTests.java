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
import java.nio.ByteBuffer;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tracker numbers tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class TrackerNumberTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testTrackerNumber() {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();
    assertThat(trackerNumber.hashCode()).isNotNull();
    assertThat(trackerNumber.getTrackerNumber()).isEqualTo(number);
    assertThat(trackerNumber.getTrackerNumberInGroup()).isEqualTo(trackerNumberInGroup);
    assertThat(trackerNumber.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final byte[] bytes = trackerNumber.getBytes();
    assertThat(bytes).isNotNull();
    assertThat(ByteBuffer.wrap(bytes).getInt()).isEqualTo(number);

    final TrackerNumber anotherTrackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);
    assertThat(anotherTrackerNumber).isNotNull();
    assertThat(anotherTrackerNumber.hashCode()).isNotNull();
    assertThat(anotherTrackerNumber.getTrackerNumber()).isEqualTo(number);

    final TrackerNumber yetAnotherTrackerNumber = new TrackerNumber(number - 1, trackerNumberInGroup, encryptedTrackerNumberInGroup);
    assertThat(yetAnotherTrackerNumber).isNotNull();
    assertThat(yetAnotherTrackerNumber.hashCode()).isNotNull();
    assertThat(yetAnotherTrackerNumber.getTrackerNumber()).isNotEqualTo(number);

    assertThat(anotherTrackerNumber.equals(trackerNumber)).isTrue();
    assertThat(anotherTrackerNumber.hashCode()).isEqualTo(trackerNumber.hashCode());
    assertThat(yetAnotherTrackerNumber.equals(trackerNumber)).isFalse();
    assertThat(yetAnotherTrackerNumber.hashCode()).isNotEqualTo(trackerNumber.hashCode());
  }

  @Test
  public void testTrackerNumberSerialiseAll() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isEqualTo(number);
    assertThat(read.getTrackerNumberInGroup()).isEqualTo(trackerNumberInGroup);
    assertThat(read.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testTrackerNumberSerialiseERSVoteImport() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSVoteImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSVoteImport.class);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).withView(JacksonViews.ERSVoteImport.class).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumberInGroup()).isNull();
    assertThat(read.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testTrackerNumberSerialiseMixed() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Mixed.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Mixed.class);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).withView(JacksonViews.Mixed.class).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumberInGroup()).isNull();
    assertThat(read.getEncryptedTrackerNumberInGroup()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testTrackerNumberSerialisePublic() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumberInGroup()).isNull();
    assertThat(read.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testTrackerNumberSerialiseRestrictedPublic() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.RestrictedPublic.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.RestrictedPublic.class);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).withView(JacksonViews.RestrictedPublic.class).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isEqualTo(number);
    assertThat(read.getTrackerNumberInGroup()).isEqualTo(trackerNumberInGroup);
    assertThat(read.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testTrackerNumberSerialiseVote() throws Exception {
    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    assertThat(trackerNumber).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Vote.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(TrackerNumber.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Vote.class);
    final String csv = writer.writeValueAsString(trackerNumber);
    final MappingIterator<Object> iterator = csvMapper.readerFor(TrackerNumber.class).with(schema).withView(JacksonViews.Vote.class).readValues(csv);
    final TrackerNumber read = (TrackerNumber) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumberInGroup()).isNull();
    assertThat(read.getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
