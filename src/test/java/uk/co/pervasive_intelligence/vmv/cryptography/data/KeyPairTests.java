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
 * Key pair tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class KeyPairTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testKeyPair() {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPrivateKey()).isEqualTo(privateKey);
    assertThat(keyPair.getPublicKey()).isEqualTo(publicKey);
  }

  @Test
  public void testKeyPairSerialiseAll() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isEqualTo(keyPair.getPrivateKey());
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testKeyPairSerialiseERSKeyImport() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSKeyImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSKeyImport.class);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).withView(JacksonViews.ERSKeyImport.class).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isNull();
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testKeyPairSerialiseERSVoteImport() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSVoteImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSVoteImport.class);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).withView(JacksonViews.ERSVoteImport.class).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isNull();
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testKeyPairSerialisePublic() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isNull();
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testKeyPairSerialiseVote() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Vote.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Vote.class);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).withView(JacksonViews.Vote.class).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isNull();
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testKeyPairSerialiseVoterVote() throws Exception {
    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);

    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    assertThat(keyPair).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.VoterVote.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(KeyPair.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.VoterVote.class);
    final String csv = writer.writeValueAsString(keyPair);
    final MappingIterator<Object> iterator = csvMapper.readerFor(KeyPair.class).with(schema).withView(JacksonViews.VoterVote.class).readValues(csv);
    final KeyPair read = (KeyPair) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPrivateKey()).isNull();
    assertThat(read.getPublicKey()).isEqualTo(keyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
