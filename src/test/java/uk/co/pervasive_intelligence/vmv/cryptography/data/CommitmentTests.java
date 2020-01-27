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
 * Commitment tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CommitmentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testCommitment() {
    final Commitment commitment = new Commitment();
    assertThat(commitment).isNotNull();

    final BigInteger h = BigInteger.ONE;
    commitment.setH(h);
    assertThat(commitment.getH()).isEqualTo(h);

    final BigInteger g = BigInteger.TEN;
    commitment.setG(g);
    assertThat(commitment.getG()).isEqualTo(g);

    final BigInteger publicKey = BigInteger.ZERO;
    commitment.setPublicKey(publicKey);
    assertThat(commitment.getPublicKey()).isEqualTo(publicKey);

    final byte[] encryptedH = new byte[2];
    commitment.setEncryptedH(encryptedH);
    assertThat(commitment.getEncryptedH()).isEqualTo(encryptedH);

    final byte[] encryptedG = new byte[3];
    commitment.setEncryptedG(encryptedG);
    assertThat(commitment.getEncryptedG()).isEqualTo(encryptedG);
  }

  @Test
  public void testCommitmentSerialiseAll() throws Exception {
    final BigInteger random = BigInteger.TEN;
    final BigInteger h = BigInteger.ONE;
    final BigInteger g = BigInteger.TEN;
    final BigInteger publicKey = BigInteger.ZERO;
    final byte[] encryptedH = new byte[2];
    final byte[] encryptedG = new byte[3];
    final Commitment commitment = new Commitment();
    assertThat(commitment).isNotNull();

    commitment.setPublicKey(publicKey);
    commitment.setEncryptedH(encryptedH);
    commitment.setEncryptedG(encryptedG);
    commitment.setH(h);
    commitment.setG(g);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Commitment.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(commitment);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Commitment.class).with(schema).readValues(csv);
    final Commitment read = (Commitment) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPublicKey()).isEqualTo(publicKey);
    assertThat(read.getH()).isEqualTo(h);
    assertThat(read.getG()).isEqualTo(g);
    assertThat(read.getEncryptedH()).isEqualTo(encryptedH);
    assertThat(read.getEncryptedG()).isEqualTo(encryptedG);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testCommitmentSerialisePublic() throws Exception {
    final BigInteger random = BigInteger.TEN;
    final BigInteger h = BigInteger.ONE;
    final BigInteger g = BigInteger.TEN;
    final BigInteger publicKey = BigInteger.ZERO;
    final byte[] encryptedH = new byte[2];
    final byte[] encryptedG = new byte[3];
    final Commitment commitment = new Commitment();
    assertThat(commitment).isNotNull();

    commitment.setPublicKey(publicKey);
    commitment.setEncryptedH(encryptedH);
    commitment.setEncryptedG(encryptedG);
    commitment.setH(h);
    commitment.setG(g);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Commitment.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(commitment);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Commitment.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final Commitment read = (Commitment) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getPublicKey()).isEqualTo(publicKey);
    assertThat(read.getH()).isNull();
    assertThat(read.getG()).isNull();
    assertThat(read.getEncryptedH()).isEqualTo(encryptedH);
    assertThat(read.getEncryptedG()).isEqualTo(encryptedG);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
