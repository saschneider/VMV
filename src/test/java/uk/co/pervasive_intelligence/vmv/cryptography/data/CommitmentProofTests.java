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
 * Commitment proof tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CommitmentProofTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testCommitmentProof() {
    final BigInteger a1Dash = BigInteger.TEN;
    final BigInteger a2Dash = BigInteger.ONE;
    final BigInteger b1Dash = BigInteger.ZERO;
    final BigInteger b2Dash = BigInteger.TEN;
    final BigInteger c = BigInteger.ONE;
    final BigInteger d = BigInteger.ZERO;
    final Proof pi11 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(1));
    final Proof pi12 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(2));
    final Proof pi21 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(1));
    final Proof pi22 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(2));
    final Proof pi23 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(3));
    final Proof pi31 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(1));
    final Proof pi32 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(2));
    final Proof pi4 = new Proof(BigInteger.valueOf(4), BigInteger.valueOf(0));
    final Proof pi5 = new Proof(BigInteger.valueOf(5), BigInteger.valueOf(0));

    final CommitmentProof commitmentProof = new CommitmentProof(a1Dash, a2Dash, b1Dash, b2Dash, c, d, pi11, pi12, pi21, pi22, pi23, pi31, pi32, pi4, pi5);
    assertThat(commitmentProof).isNotNull();

    assertThat(commitmentProof.getA1Dash()).isEqualTo(a1Dash);
    assertThat(commitmentProof.getA2Dash()).isEqualTo(a2Dash);
    assertThat(commitmentProof.getB1Dash()).isEqualTo(b1Dash);
    assertThat(commitmentProof.getB2Dash()).isEqualTo(b2Dash);
    assertThat(commitmentProof.getC()).isEqualTo(c);
    assertThat(commitmentProof.getD()).isEqualTo(d);

    assertThat(commitmentProof.getPi11()).isNotNull();
    assertThat(commitmentProof.getPi11().getHash()).isEqualTo(pi11.getHash());
    assertThat(commitmentProof.getPi11().getSignature()).isEqualTo(pi11.getSignature());

    assertThat(commitmentProof.getPi12()).isNotNull();
    assertThat(commitmentProof.getPi12().getHash()).isEqualTo(pi12.getHash());
    assertThat(commitmentProof.getPi12().getSignature()).isEqualTo(pi12.getSignature());

    assertThat(commitmentProof.getPi21()).isNotNull();
    assertThat(commitmentProof.getPi21().getHash()).isEqualTo(pi21.getHash());
    assertThat(commitmentProof.getPi21().getSignature()).isEqualTo(pi21.getSignature());

    assertThat(commitmentProof.getPi22()).isNotNull();
    assertThat(commitmentProof.getPi22().getHash()).isEqualTo(pi22.getHash());
    assertThat(commitmentProof.getPi22().getSignature()).isEqualTo(pi22.getSignature());

    assertThat(commitmentProof.getPi23()).isNotNull();
    assertThat(commitmentProof.getPi23().getHash()).isEqualTo(pi23.getHash());
    assertThat(commitmentProof.getPi23().getSignature()).isEqualTo(pi23.getSignature());

    assertThat(commitmentProof.getPi31()).isNotNull();
    assertThat(commitmentProof.getPi31().getHash()).isEqualTo(pi31.getHash());
    assertThat(commitmentProof.getPi31().getSignature()).isEqualTo(pi31.getSignature());

    assertThat(commitmentProof.getPi32()).isNotNull();
    assertThat(commitmentProof.getPi32().getHash()).isEqualTo(pi32.getHash());
    assertThat(commitmentProof.getPi32().getSignature()).isEqualTo(pi32.getSignature());

    assertThat(commitmentProof.getPi4()).isNotNull();
    assertThat(commitmentProof.getPi4().getHash()).isEqualTo(pi4.getHash());
    assertThat(commitmentProof.getPi4().getSignature()).isEqualTo(pi4.getSignature());

    assertThat(commitmentProof.getPi5()).isNotNull();
    assertThat(commitmentProof.getPi5().getHash()).isEqualTo(pi5.getHash());
    assertThat(commitmentProof.getPi5().getSignature()).isEqualTo(pi5.getSignature());
  }

  @Test
  public void testCommitmentProofSerialiseAll() throws Exception {
    final BigInteger a1Dash = BigInteger.TEN;
    final BigInteger a2Dash = BigInteger.ONE;
    final BigInteger b1Dash = BigInteger.ZERO;
    final BigInteger b2Dash = BigInteger.TEN;
    final BigInteger c = BigInteger.ONE;
    final BigInteger d = BigInteger.ZERO;
    final Proof pi11 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(1));
    final Proof pi12 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(2));
    final Proof pi21 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(1));
    final Proof pi22 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(2));
    final Proof pi23 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(3));
    final Proof pi31 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(1));
    final Proof pi32 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(2));
    final Proof pi4 = new Proof(BigInteger.valueOf(4), BigInteger.valueOf(0));
    final Proof pi5 = new Proof(BigInteger.valueOf(5), BigInteger.valueOf(0));
    final CommitmentProof commitmentProof = new CommitmentProof(a1Dash, a2Dash, b1Dash, b2Dash, c, d, pi11, pi12, pi21, pi22, pi23, pi31, pi32, pi4, pi5);
    assertThat(commitmentProof).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(CommitmentProof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(commitmentProof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(CommitmentProof.class).with(schema).readValues(csv);
    final CommitmentProof read = (CommitmentProof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getA1Dash()).isEqualTo(a1Dash);
    assertThat(read.getA2Dash()).isEqualTo(a2Dash);
    assertThat(read.getB1Dash()).isEqualTo(b1Dash);
    assertThat(read.getB2Dash()).isEqualTo(b2Dash);
    assertThat(read.getC()).isEqualTo(c);
    assertThat(read.getD()).isEqualTo(d);

    assertThat(read.getPi11()).isNotNull();
    assertThat(read.getPi11().getHash()).isEqualTo(pi11.getHash());
    assertThat(read.getPi11().getSignature()).isEqualTo(pi11.getSignature());

    assertThat(read.getPi12()).isNotNull();
    assertThat(read.getPi12().getHash()).isEqualTo(pi12.getHash());
    assertThat(read.getPi12().getSignature()).isEqualTo(pi12.getSignature());

    assertThat(read.getPi21()).isNotNull();
    assertThat(read.getPi21().getHash()).isEqualTo(pi21.getHash());
    assertThat(read.getPi21().getSignature()).isEqualTo(pi21.getSignature());

    assertThat(read.getPi22()).isNotNull();
    assertThat(read.getPi22().getHash()).isEqualTo(pi22.getHash());
    assertThat(read.getPi22().getSignature()).isEqualTo(pi22.getSignature());

    assertThat(read.getPi23()).isNotNull();
    assertThat(read.getPi23().getHash()).isEqualTo(pi23.getHash());
    assertThat(read.getPi23().getSignature()).isEqualTo(pi23.getSignature());

    assertThat(read.getPi31()).isNotNull();
    assertThat(read.getPi31().getHash()).isEqualTo(pi31.getHash());
    assertThat(read.getPi31().getSignature()).isEqualTo(pi31.getSignature());

    assertThat(read.getPi32()).isNotNull();
    assertThat(read.getPi32().getHash()).isEqualTo(pi32.getHash());
    assertThat(read.getPi32().getSignature()).isEqualTo(pi32.getSignature());

    assertThat(read.getPi4()).isNotNull();
    assertThat(read.getPi4().getHash()).isEqualTo(pi4.getHash());
    assertThat(read.getPi4().getSignature()).isEqualTo(pi4.getSignature());

    assertThat(read.getPi5()).isNotNull();
    assertThat(read.getPi5().getHash()).isEqualTo(pi5.getHash());
    assertThat(read.getPi5().getSignature()).isEqualTo(pi5.getSignature());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testCommitmentProofSerialisePublic() throws Exception {
    final BigInteger a1Dash = BigInteger.TEN;
    final BigInteger a2Dash = BigInteger.ONE;
    final BigInteger b1Dash = BigInteger.ZERO;
    final BigInteger b2Dash = BigInteger.TEN;
    final BigInteger c = BigInteger.ONE;
    final BigInteger d = BigInteger.ZERO;
    final Proof pi11 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(1));
    final Proof pi12 = new Proof(BigInteger.valueOf(1), BigInteger.valueOf(2));
    final Proof pi21 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(1));
    final Proof pi22 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(2));
    final Proof pi23 = new Proof(BigInteger.valueOf(2), BigInteger.valueOf(3));
    final Proof pi31 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(1));
    final Proof pi32 = new Proof(BigInteger.valueOf(3), BigInteger.valueOf(2));
    final Proof pi4 = new Proof(BigInteger.valueOf(4), BigInteger.valueOf(0));
    final Proof pi5 = new Proof(BigInteger.valueOf(5), BigInteger.valueOf(0));
    final CommitmentProof commitmentProof = new CommitmentProof(a1Dash, a2Dash, b1Dash, b2Dash, c, d, pi11, pi12, pi21, pi22, pi23, pi31, pi32, pi4, pi5);
    assertThat(commitmentProof).isNotNull();

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(CommitmentProof.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(commitmentProof);
    final MappingIterator<Object> iterator = csvMapper.readerFor(CommitmentProof.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final CommitmentProof read = (CommitmentProof) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getA1Dash()).isEqualTo(a1Dash);
    assertThat(read.getA2Dash()).isEqualTo(a2Dash);
    assertThat(read.getB1Dash()).isEqualTo(b1Dash);
    assertThat(read.getB2Dash()).isEqualTo(b2Dash);
    assertThat(read.getC()).isEqualTo(c);
    assertThat(read.getD()).isEqualTo(d);

    assertThat(read.getPi11()).isNotNull();
    assertThat(read.getPi11().getHash()).isEqualTo(pi11.getHash());
    assertThat(read.getPi11().getSignature()).isEqualTo(pi11.getSignature());

    assertThat(read.getPi12()).isNotNull();
    assertThat(read.getPi12().getHash()).isEqualTo(pi12.getHash());
    assertThat(read.getPi12().getSignature()).isEqualTo(pi12.getSignature());

    assertThat(read.getPi21()).isNotNull();
    assertThat(read.getPi21().getHash()).isEqualTo(pi21.getHash());
    assertThat(read.getPi21().getSignature()).isEqualTo(pi21.getSignature());

    assertThat(read.getPi22()).isNotNull();
    assertThat(read.getPi22().getHash()).isEqualTo(pi22.getHash());
    assertThat(read.getPi22().getSignature()).isEqualTo(pi22.getSignature());

    assertThat(read.getPi23()).isNotNull();
    assertThat(read.getPi23().getHash()).isEqualTo(pi23.getHash());
    assertThat(read.getPi23().getSignature()).isEqualTo(pi23.getSignature());

    assertThat(read.getPi31()).isNotNull();
    assertThat(read.getPi31().getHash()).isEqualTo(pi31.getHash());
    assertThat(read.getPi31().getSignature()).isEqualTo(pi31.getSignature());

    assertThat(read.getPi32()).isNotNull();
    assertThat(read.getPi32().getHash()).isEqualTo(pi32.getHash());
    assertThat(read.getPi32().getSignature()).isEqualTo(pi32.getSignature());

    assertThat(read.getPi4()).isNotNull();
    assertThat(read.getPi4().getHash()).isEqualTo(pi4.getHash());
    assertThat(read.getPi4().getSignature()).isEqualTo(pi4.getSignature());

    assertThat(read.getPi5()).isNotNull();
    assertThat(read.getPi5().getHash()).isEqualTo(pi5.getHash());
    assertThat(read.getPi5().getSignature()).isEqualTo(pi5.getSignature());

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
