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
 * Encryption proof tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class EncryptProofTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testEncryptProof() {
    final BigInteger c1R = BigInteger.TEN;
    final BigInteger c2R = BigInteger.ONE;
    final BigInteger c1Bar = BigInteger.ZERO;
    final BigInteger c2Bar = BigInteger.TEN;
    final byte[] signature = new byte[] {1, 2, 3, 4, 5, 6};

    final EncryptProof encryptProof = new EncryptProof(c1R, c2R, c1Bar, c2Bar, signature);
    assertThat(encryptProof).isNotNull();

    assertThat(encryptProof.getC1R()).isEqualTo(c1R);
    assertThat(encryptProof.getC2R()).isEqualTo(c2R);
    assertThat(encryptProof.getC1Bar()).isEqualTo(c1Bar);
    assertThat(encryptProof.getC2Bar()).isEqualTo(c2Bar);
    assertThat(encryptProof.getEncryptedVoteSignature()).isEqualTo(signature);
  }

  @Test
  public void testEncryptProofSerialiseAll() throws Exception {
    final BigInteger c1R = BigInteger.TEN;
    final BigInteger c2R = BigInteger.ONE;
    final BigInteger c1Bar = BigInteger.ZERO;
    final BigInteger c2Bar = BigInteger.TEN;
    final byte[] signature = new byte[] {1, 2, 3, 4, 5, 6};
    final EncryptProof encryptProof = new EncryptProof(c1R, c2R, c1Bar, c2Bar, signature);
    assertThat(encryptProof).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(EncryptProof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(encryptProof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(EncryptProof.class).with(schema).readValues(csv);
    final EncryptProof read = (EncryptProof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getC1R()).isEqualTo(c1R);
    assertThat(read.getC2R()).isEqualTo(c2R);
    assertThat(read.getC1Bar()).isEqualTo(c1Bar);
    assertThat(read.getC2Bar()).isEqualTo(c2Bar);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(signature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testEncryptProofSerialisePublic() throws Exception {
    final BigInteger c1R = BigInteger.TEN;
    final BigInteger c2R = BigInteger.ONE;
    final BigInteger c1Bar = BigInteger.ZERO;
    final BigInteger c2Bar = BigInteger.TEN;
    final byte[] signature = new byte[] {1, 2, 3, 4, 5, 6};
    final EncryptProof encryptProof = new EncryptProof(c1R, c2R, c1Bar, c2Bar, signature);
    assertThat(encryptProof).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(EncryptProof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(encryptProof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(EncryptProof.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final EncryptProof read = (EncryptProof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getC1R()).isEqualTo(c1R);
    assertThat(read.getC2R()).isEqualTo(c2R);
    assertThat(read.getC1Bar()).isEqualTo(c1Bar);
    assertThat(read.getC2Bar()).isEqualTo(c2Bar);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(signature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
