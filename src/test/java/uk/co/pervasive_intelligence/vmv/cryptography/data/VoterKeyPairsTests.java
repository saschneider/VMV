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
 * Voter key pairs tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VoterKeyPairsTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testVoterKeyPairs() {
    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);
    assertThat(voterKeyPairs).isNotNull();
    assertThat(voterKeyPairs.getTrapdoorKeyPair()).isEqualTo(trapdoorKeyPair);
    assertThat(voterKeyPairs.getSignatureKeyPair()).isEqualTo(signatureKeyPair);
  }

  @Test
  public void testVoterKeyPairsSerialise() throws Exception {
    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);
    assertThat(voterKeyPairs).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(VoterKeyPairs.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(voterKeyPairs);
    final MappingIterator<Object> iterator = csvMapper.readerFor(VoterKeyPairs.class).with(schema).readValues(csv);
    final VoterKeyPairs read = (VoterKeyPairs) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrapdoorKeyPair().getPrivateKey()).isEqualTo(trapdoorKeyPair.getPrivateKey());
    assertThat(read.getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getSignatureKeyPair().getPrivateKey()).isEqualTo(signatureKeyPair.getPrivateKey());
    assertThat(read.getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterKeyPairsSerialisePublic() throws Exception {
    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);
    assertThat(voterKeyPairs).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(VoterKeyPairs.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(voterKeyPairs);
    final MappingIterator<Object> iterator = csvMapper.readerFor(VoterKeyPairs.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final VoterKeyPairs read = (VoterKeyPairs) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
