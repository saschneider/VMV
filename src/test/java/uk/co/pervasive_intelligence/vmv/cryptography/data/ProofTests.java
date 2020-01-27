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
 * Proof tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ProofTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testProof() {
    final Proof proof = new Proof();
    assertThat(proof).isNotNull();

    final BigInteger hash = BigInteger.TEN;
    proof.setHash(hash);
    assertThat(proof.getHash()).isEqualTo(hash);

    final BigInteger signature = BigInteger.ONE;
    proof.setSignature(signature);
    assertThat(proof.getSignature()).isEqualTo(signature);
  }

  @Test
  public void testProofSerialiseAll() throws Exception {
    final BigInteger hash = BigInteger.TEN;
    final BigInteger signature = BigInteger.ONE;
    final Proof proof = new Proof(hash, signature);
    assertThat(proof).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Proof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(proof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Proof.class).with(schema).readValues(csv);
    final Proof read = (Proof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getHash()).isEqualTo(hash);
    assertThat(read.getSignature()).isEqualTo(signature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testProofSerialisePublic() throws Exception {
    final BigInteger hash = BigInteger.TEN;
    final BigInteger signature = BigInteger.ONE;
    final Proof proof = new Proof(hash, signature);
    assertThat(proof).isNotNull();

    proof.setHash(hash);
    proof.setSignature(signature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Proof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(proof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Proof.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final Proof read = (Proof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getHash()).isEqualTo(hash);
    assertThat(read.getSignature()).isEqualTo(signature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
