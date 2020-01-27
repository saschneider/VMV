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
 * Voter tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VoterTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testVoter() {
    final long id = 1234L;
    final Voter voter = new Voter();
    assertThat(voter).isNotNull();

    voter.setId(id);
    assertThat(voter.getId()).isEqualTo(id);

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);
    assertThat(voter.getVoterKeyPairs()).isEqualTo(voterKeyPairs);
    assertThat(voter.getTrackerNumber()).isEqualTo(trackerNumber);
    assertThat(voter.getTrackerNumber().getTrackerNumberInGroup()).isEqualTo(trackerNumberInGroup);
    assertThat(voter.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(voter.getAlpha()).isEqualTo(alpha);
    assertThat(voter.getBeta()).isEqualTo(beta);
    assertThat(voter.getPlainTextVote()).isEqualTo(plainTextVote);
    assertThat(voter.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(voter.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);
  }

  @Test
  public void testVoterSerialiseAll() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper();
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isEqualTo(trapdoorKeyPair.getPrivateKey());
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isEqualTo(signatureKeyPair.getPrivateKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isEqualTo(trackerNumber);
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isEqualTo(trackerNumberInGroup);
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isEqualTo(alpha);
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isEqualTo(plainTextVote);
    assertThat(read.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSExport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSExport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSExport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSExport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSImport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSImport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSImport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isNull();
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isNull();
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSKeyImport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSKeyImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSKeyImport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSKeyImport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isNull();
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSVoteEncryptedImport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSVoteEncryptedImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSVoteEncryptedImport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSVoteEncryptedImport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isEqualTo(plainTextVote);
    assertThat(read.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSVoteExport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSVoteExport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSVoteExport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSVoteExport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isNull();
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(read.getAlpha()).isEqualTo(alpha);
    assertThat(read.getBeta()).isNull();
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseERSVoteImport() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.ERSVoteImport.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.ERSVoteImport.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.ERSVoteImport.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isEqualTo(id);
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isEqualTo(plainTextVote);
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseMixed() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Mixed.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Mixed.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.Mixed.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isNull();
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isNull();
    assertThat(read.getPlainTextVote()).isNotNull();
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialisePublic() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Public.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Public.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.Public.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorKeyPair.getPublicKey());
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signatureKeyPair.getPublicKey());
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isNull();
    assertThat(read.getEncryptedVoteSignature()).isNull();

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseVote() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.Vote.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.Vote.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.Vote.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorPublicKey);
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signaturePublicKey);
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isEqualTo(beta);
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }

  @Test
  public void testVoterSerialiseVoterVote() throws Exception {
    final long id = 1234L;
    final Voter voter = new Voter(id);
    assertThat(voter).isNotNull();

    final BigInteger trapdoorPrivateKey = BigInteger.valueOf(123);
    final BigInteger trapdoorPublicKey = BigInteger.valueOf(456);
    final KeyPair trapdoorKeyPair = new KeyPair(trapdoorPrivateKey, trapdoorPublicKey);

    final BigInteger signaturePrivateKey = BigInteger.valueOf(789);
    final BigInteger signaturePublicKey = BigInteger.valueOf(101112);
    final KeyPair signatureKeyPair = new KeyPair(signaturePrivateKey, signaturePublicKey);

    final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

    final int number = 4321;
    final BigInteger trackerNumberInGroup = BigInteger.ONE;
    final byte[] encryptedTrackerNumberInGroup = new byte[64];
    final TrackerNumber trackerNumber = new TrackerNumber(number, trackerNumberInGroup, encryptedTrackerNumberInGroup);

    final BigInteger alpha = BigInteger.ZERO;
    final BigInteger beta = BigInteger.TEN;

    final String plainTextVote = "Test Vote";
    final byte[] encryptedVote = new byte[128];
    final byte[] encryptedVoteSignature = new byte[24];

    voter.setVoterKeyPairs(voterKeyPairs);
    voter.setTrackerNumber(trackerNumber);
    voter.setAlpha(alpha);
    voter.setBeta(beta);
    voter.setPlainTextVote(plainTextVote);
    voter.setEncryptedVote(encryptedVote);
    voter.setEncryptedVoteSignature(encryptedVoteSignature);

    final BaseShellComponent.ApplyViewCsvMapper csvMapper = new BaseShellComponent.ApplyViewCsvMapper(JacksonViews.VoterVote.class);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);
    final CsvSchema schema = csvMapper.schemaFor(Voter.class).withHeader();
    final ObjectWriter writer = csvMapper.writer().with(schema).withView(JacksonViews.VoterVote.class);
    final String csv = writer.writeValueAsString(voter);
    final MappingIterator<Object> iterator = csvMapper.readerFor(Voter.class).with(schema).withView(JacksonViews.VoterVote.class).readValues(csv);
    final Voter read = (Voter) iterator.nextValue();
    assertThat(read).isNotNull();
    assertThat(read.getId()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isEqualTo(trapdoorPublicKey);
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPrivateKey()).isNull();
    assertThat(read.getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isEqualTo(signaturePublicKey);
    assertThat(read.getTrackerNumber()).isNotNull();
    assertThat(read.getTrackerNumber().getTrackerNumber()).isNull();
    assertThat(read.getTrackerNumber().getTrackerNumberInGroup()).isNull();
    assertThat(read.getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(read.getAlpha()).isNull();
    assertThat(read.getBeta()).isNull();
    assertThat(read.getPlainTextVote()).isNull();
    assertThat(read.getEncryptedVote()).isEqualTo(encryptedVote);
    assertThat(read.getEncryptedVoteSignature()).isEqualTo(encryptedVoteSignature);

    final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
    final Set<ConstraintViolation<Object>> valid = validator.validate(read);
    assertThat(valid).isEmpty();
  }
}
