/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.bouncycastle.crypto.params.DHParameters;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.context.MessageSource;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseShellComponent;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.ChaumPedersenAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.SchnorrAlgorithmHelper;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Selene cryptography helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class SeleneCryptographyHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Mock
  private ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper;

  @Mock
  private DSAAlgorithmHelper dsaAlgorithmHelper;

  @Mock
  private ElGamalAlgorithmHelper elgamalAlgorithmHelper;

  @Mock
  private MessageSource messageSource;

  @Mock
  private SchnorrAlgorithmHelper schnorrAlgorithmHelper;

  @Mock
  private VerificatumHelper verificatumHelper;

  @Test
  public void testAssociateVoters() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    final List<Voter> ersVoters = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      final KeyPair trapdoorKeyPair = new KeyPair(null, BigInteger.valueOf(100 + i));
      final KeyPair signatureKeyPair = new KeyPair(null, BigInteger.valueOf(200 + i));
      final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);

      keyPairs.add(voterKeyPairs);

      final Voter voter = new Voter(i);

      if ((i == 0) || (i == (voters - 1))) {
        voter.setVoterKeyPairs(voterKeyPairs);
      }

      ersVoters.add(voter);
    }

    final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < voters; i++) {
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});
    Mockito.when(this.elgamalAlgorithmHelper.decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(BigInteger.TEN.toByteArray());

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final int teller = 1;
    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, keyPair, keyPairs, shuffledTrackerNumbersWithProof.getObject());
    final ProofWrapper<List<Voter>> votersWithProof = helper.decryptCommitments(wrapper, keyPair, teller, keyPairs, trackerNumbersList,
        Collections.singletonList(commitmentsWithProof.getObject()));

    final List<Voter> votersList = votersWithProof.getObject();
    helper.associateVoters(ersVoters, votersList);

    for (int i = 0; i < voters; i++) {
      assertThat(votersList.get(i).getId()).isEqualTo(ersVoters.get(i).getId());
      assertThat(votersList.get(i).getAlpha()).isNull();
      assertThat(votersList.get(i).getBeta()).isNotNull();
      assertThat(votersList.get(i).getVoterKeyPairs()).isEqualTo(keyPairs.get(i));
      assertThat(votersList.get(i).getTrackerNumber()).isEqualTo(trackerNumbersList.get(i));
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
  }

  @Test
  public void testAssociateVotersWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<Voter> ersVoters = Arrays.asList(new Voter(), new Voter());
    final List<Voter> votersList = Arrays.asList(new Voter(), new Voter(), new Voter());

    this.exception.expect(CryptographyException.class);
    helper.associateVoters(ersVoters, votersList);
  }

  @Test
  public void testCompleteCommitmentsVotes() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<Voter> voters = new ArrayList<>();
    final List<Commitment> commitments = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final BigInteger publicKey = BigInteger.valueOf(i);

      final Voter voter = new Voter(i);
      voter.setVoterKeyPairs(new VoterKeyPairs(new KeyPair(null, publicKey), null));
      voters.add(voter);

      final Commitment commitment = new Commitment();
      commitment.setG(BigInteger.ONE);
      commitment.setPublicKey(publicKey);
      commitments.add(commitment);
    }
    final List<List<Commitment>> tellerCommitments = Collections.singletonList(commitments);

    helper.completeCommitments(wrapper, voters, tellerCommitments);

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = voters.get(i);
      assertThat(voter).isNotNull();
      assertThat(voter.getAlpha()).isEqualTo(BigInteger.ONE);
    }
  }

  @Test
  public void testCompleteCommitmentsWrongPublicKey() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<Voter> voters = new ArrayList<>();
    final List<Commitment> commitments = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final BigInteger publicKey = BigInteger.valueOf(i);

      final Voter voter = new Voter(i);
      voter.setVoterKeyPairs(new VoterKeyPairs(new KeyPair(null, null), null));
      voters.add(voter);

      final Commitment commitment = new Commitment();
      commitment.setG(BigInteger.ONE);
      commitment.setPublicKey(publicKey);
      commitments.add(commitment);
    }
    final List<List<Commitment>> tellerCommitments = Collections.singletonList(commitments);

    this.exception.expect(CryptographyException.class);
    helper.completeCommitments(wrapper, voters, tellerCommitments);
  }

  @Test
  public void testCompleteCommitmentsWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<Voter> voters = Arrays.asList(new Voter(1), new Voter(2), new Voter(3));
    final List<List<Commitment>> commitments = Collections.singletonList(Collections.singletonList(new Commitment()));

    this.exception.expect(CryptographyException.class);
    helper.completeCommitments(null, voters, commitments);
  }

  @Test
  public void testCreateCommitments() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));
    }

    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final int teller = 1;
    final File proofFile = Files.createTempFile(null, null).toFile();
    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, keyPair, keyPairs, shuffledTrackerNumbersWithProof.getObject());
    assertThat(commitmentsWithProof).isNotNull();
    assertThat(commitmentsWithProof.getProofFile()).isNotNull();
    assertThat(commitmentsWithProof.getObject()).isNotNull();
    assertThat(commitmentsWithProof.getObject().size()).isEqualTo(voters);

    for (int i = 0; i < voters; i++) {
      final Commitment commitment = commitmentsWithProof.getObject().get(i);
      assertThat(commitment).isNotNull();
      assertThat(commitment.getH()).isNotNull();
      assertThat(commitment.getG()).isNotNull();
      assertThat(commitment.getEncryptedH()).isNotNull();
      assertThat(commitment.getEncryptedG()).isNotNull();
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
    proofFile.delete();
  }

  @Test
  public void testCreateCommitmentsNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));
    }

    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
    for (int i = 0; i < voters; i++) {
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final int teller = 1;
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, keyPair, keyPairs, shuffledTrackerNumbersWithProof.getObject());
    assertThat(commitmentsWithProof).isNotNull();
    assertThat(commitmentsWithProof.getProofFile()).isNotNull();
    assertThat(commitmentsWithProof.getObject()).isNotNull();
    assertThat(commitmentsWithProof.getObject().size()).isEqualTo(voters);

    for (int i = 0; i < voters; i++) {
      final Commitment commitment = commitmentsWithProof.getObject().get(i);
      assertThat(commitment).isNotNull();
      assertThat(commitment.getH()).isNotNull();
      assertThat(commitment.getG()).isNotNull();
      assertThat(commitment.getEncryptedH()).isNotNull();
      assertThat(commitment.getEncryptedG()).isNotNull();
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
  }

  @Test
  public void testCreateCommitmentsWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<VoterKeyPairs> keyPairs = Arrays.asList(new VoterKeyPairs(null, null), new VoterKeyPairs(null, null));
    final List<TrackerNumber> trackerNumbers = Arrays.asList(new TrackerNumber(1, BigInteger.ONE, null), new TrackerNumber(1, BigInteger.ONE, null),
        new TrackerNumber(1, BigInteger.ONE, null));

    this.exception.expect(CryptographyException.class);
    helper.createCommitments(null, null, keyPairs, trackerNumbers);
  }

  @Test
  public void testCreateElectionKeyPair() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair dummyKeyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.verificatumHelper.createElectionKeyPair(Mockito.isNotNull(), Mockito.anyInt())).thenReturn(dummyKeyPair);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final KeyPair keyPair = helper.createElectionKeyPair(wrapper, 1);
    assertThat(keyPair).isNotNull();
  }

  @Test
  public void testCreateElectionKeyPairNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(0);
    wrapper.setThresholdTellers(0);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair dummyKeyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.dsaAlgorithmHelper.createKeys(Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(dummyKeyPair);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final KeyPair keyPair = helper.createElectionKeyPair(wrapper, 0);
    assertThat(keyPair).isNotNull();
  }

  @Test
  public void testCreateElectionKeyPairWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair dummyKeyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.dsaAlgorithmHelper.createKeys(Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(dummyKeyPair);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.createElectionKeyPair(wrapper, 0);
  }

  @Test
  public void testCreateElectionParameters() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    Mockito.when(this.dsaAlgorithmHelper.createParameters(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(wrapper);
    Mockito.<Class<?>>when(this.dsaAlgorithmHelper.getParametersClass()).thenReturn(wrapper.getClass());

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final Object[] options = new Object[] {1024, 160};
    final Object parameters = helper.createElectionParameters(options);
    assertThat(parameters).isNotNull();

    assertThat(helper.getElectionParametersClass()).isEqualTo(parameters.getClass());
  }

  @Test
  public void testCreateTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;
    final String ip = CryptographyHelper.DEFAULT_TELLER_IP;
    final int tellerPort = CryptographyHelper.DEFAULT_TELLER_PORT;
    final int hintPort = CryptographyHelper.DEFAULT_HINT_PORT;

    final File file = new File("teller-information-1.xml");
    Mockito.when(this.verificatumHelper.createTeller(Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(file);

    final File tellerInformationFile = helper.createTeller(wrapper, teller, ip, tellerPort, hintPort);
    assertThat(tellerInformationFile).isNotNull();
  }

  @Test
  public void testCreateTellerNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;
    final String ip = CryptographyHelper.DEFAULT_TELLER_IP;
    final int tellerPort = CryptographyHelper.DEFAULT_TELLER_PORT;
    final int hintPort = CryptographyHelper.DEFAULT_HINT_PORT;

    this.exception.expect(CryptographyException.class);
    helper.createTeller(wrapper, teller, ip, tellerPort, hintPort);
  }

  @Test
  public void testCreateTellerWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 0;
    final String ip = CryptographyHelper.DEFAULT_TELLER_IP;
    final int tellerPort = CryptographyHelper.DEFAULT_TELLER_PORT;
    final int hintPort = CryptographyHelper.DEFAULT_HINT_PORT;

    this.exception.expect(CryptographyException.class);
    helper.createTeller(wrapper, teller, ip, tellerPort, hintPort);
  }

  @Test
  public void testCreateTrackerNumbers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray()});

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = helper.createTrackerNumbers(wrapper, keyPair, voters);
    assertThat(trackerNumbers).isNotNull();
    assertThat(trackerNumbers.size()).isEqualTo(voters);

    for (final TrackerNumber trackerNumber : trackerNumbers) {
      assertThat(trackerNumber.getTrackerNumber()).isGreaterThanOrEqualTo(SeleneCryptographyHelper.TRACKER_NUMBER_MIN);
      assertThat(trackerNumber.getTrackerNumber()).isLessThanOrEqualTo(SeleneCryptographyHelper.TRACKER_NUMBER_MAX);
      assertThat(trackerNumber.getTrackerNumberInGroup()).isNotNull();
      assertThat(trackerNumber.getEncryptedTrackerNumberInGroup()).isNotEmpty();
    }
  }

  @Test
  public void testCreateTrackerNumbersNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = helper.createTrackerNumbers(wrapper, keyPair, voters);
    assertThat(trackerNumbers).isNotNull();
    assertThat(trackerNumbers.size()).isEqualTo(voters);

    for (final TrackerNumber trackerNumber : trackerNumbers) {
      assertThat(trackerNumber.getTrackerNumber()).isGreaterThanOrEqualTo(SeleneCryptographyHelper.TRACKER_NUMBER_MIN);
      assertThat(trackerNumber.getTrackerNumber()).isLessThanOrEqualTo(SeleneCryptographyHelper.TRACKER_NUMBER_MAX);
      assertThat(trackerNumber.getTrackerNumberInGroup()).isNotNull();
      assertThat(trackerNumber.getEncryptedTrackerNumberInGroup()).isNotEmpty();
    }
  }

  @Test
  public void testCreateVoterKeyPairs() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair dummyKeyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.dsaAlgorithmHelper.createKeys(Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(dummyKeyPair);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = helper.createVotersKeyPairs(voters, wrapper);
    assertThat(keyPairs).isNotNull();
    assertThat(keyPairs.size()).isEqualTo(voters);

    for (final VoterKeyPairs keyPair : keyPairs) {
      assertThat(keyPair).isNotNull();
      assertThat(keyPair.getTrapdoorKeyPair()).isNotNull();
      assertThat(keyPair.getSignatureKeyPair()).isNotNull();
    }
  }

  @Test
  public void testDecryptCommitments() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final KeyPair electionKeyPair = new KeyPair(BigInteger.valueOf(123), BigInteger.valueOf(456));

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      final BigInteger privateKey = BigInteger.valueOf(100 + i);
      final BigInteger publicKey = BigInteger.valueOf(i);
      final KeyPair keyPair = new KeyPair(privateKey, publicKey);

      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));
    }

    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    final List<BigInteger> plainTexts = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      plainTexts.add(BigInteger.ONE);
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final int teller = 1;
    final File proofFile = Files.createTempFile(null, null).toFile();

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    final ProofWrapper<List<BigInteger>> decryptedWithProof = new ProofWrapper<>(plainTexts, proofFile);
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});
    Mockito.when(this.verificatumHelper.decrypt(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(decryptedWithProof);

    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, electionKeyPair, keyPairs,
        shuffledTrackerNumbersWithProof.getObject());

    final ProofWrapper<List<Voter>> votersWithProof = helper.decryptCommitments(wrapper, electionKeyPair, teller, keyPairs,
        trackerNumbersList, Collections.singletonList(commitmentsWithProof.getObject()));
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(voters);

    for (int i = 0; i < voters; i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      assertThat(voter.getId()).isNull();
      assertThat(voter.getAlpha()).isNull();
      assertThat(voter.getBeta()).isNotNull();
      assertThat(voter.getVoterKeyPairs()).isEqualTo(keyPairs.get(i));
      assertThat(voter.getTrackerNumber()).isEqualTo(trackerNumbersList.get(i));
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
    votersWithProof.getProofFile().delete();
    proofFile.delete();
  }

  @Test
  public void testDecryptCommitmentsNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});
    Mockito.when(this.elgamalAlgorithmHelper.decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(BigInteger.TEN.toByteArray());

    final int teller = 1;

    final File proofFile = Files.createTempFile(null, null).toFile();
    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, keyPair, keyPairs, shuffledTrackerNumbersWithProof.getObject());

    final ProofWrapper<List<Voter>> votersWithProof = helper.decryptCommitments(wrapper, keyPair, teller, keyPairs,
        trackerNumbersList, Collections.singletonList(commitmentsWithProof.getObject()));
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(voters);

    for (int i = 0; i < voters; i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      assertThat(voter.getId()).isNull();
      assertThat(voter.getAlpha()).isNull();
      assertThat(voter.getBeta()).isNotNull();
      assertThat(voter.getVoterKeyPairs()).isEqualTo(keyPairs.get(i));
      assertThat(voter.getTrackerNumber()).isEqualTo(trackerNumbersList.get(i));
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
    votersWithProof.getProofFile().delete();
  }

  @Test
  public void testDecryptCommitmentsWrongPublicKey() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final KeyPair electionKeyPair = new KeyPair(BigInteger.valueOf(123), BigInteger.valueOf(456));

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    final List<VoterKeyPairs> differentKeyPairs = new ArrayList<>();

    for (int i = 0; i < voters; i++) {
      final KeyPair keyPair = new KeyPair(BigInteger.valueOf(100 + i), BigInteger.valueOf(i));
      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));

      final KeyPair differentKeyPair = new KeyPair(BigInteger.valueOf(200 + i), BigInteger.valueOf(300 + i));
      differentKeyPairs.add(new VoterKeyPairs(differentKeyPair, differentKeyPair));
    }

    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    final List<BigInteger> plainTexts = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      plainTexts.add(BigInteger.ONE);
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final int teller = 1;
    final File proofFile = Files.createTempFile(null, null).toFile();

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    final ProofWrapper<List<BigInteger>> decryptedWithProof = new ProofWrapper<>(plainTexts, proofFile);
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});
    Mockito.when(this.verificatumHelper.decrypt(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(decryptedWithProof);

    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, electionKeyPair, keyPairs,
        shuffledTrackerNumbersWithProof.getObject());

    this.exception.expect(CryptographyException.class);
    helper.decryptCommitments(wrapper, electionKeyPair, teller, differentKeyPairs, trackerNumbersList, Collections.singletonList(commitmentsWithProof.getObject()));

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    commitmentsWithProof.getProofFile().delete();
    proofFile.delete();
  }

  @Test
  public void testDecryptCommitmentsWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<VoterKeyPairs> keyPairs = Arrays.asList(new VoterKeyPairs(null, null), new VoterKeyPairs(null, null));
    final List<TrackerNumber> trackerNumbers = Arrays.asList(new TrackerNumber(1, BigInteger.ONE, null), new TrackerNumber(1, BigInteger.ONE, null),
        new TrackerNumber(1, BigInteger.ONE, null));
    final List<Commitment> commitments = Arrays.asList(new Commitment(), new Commitment(), new Commitment(), new Commitment());

    final int teller = 1;
    this.exception.expect(CryptographyException.class);
    helper.decryptCommitments(null, null, teller, keyPairs, trackerNumbers, Collections.singletonList(commitments));
  }

  @Test
  public void testDecryptCommitmentsWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ONE, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      keyPairs.add(new VoterKeyPairs(keyPair, keyPair));
    }

    final List<CipherText> cipherTexts = new ArrayList<>();
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < voters; i++) {
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final CipherText encrypted = new CipherText(BigInteger.ONE, BigInteger.TEN);
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted.toByteArray(), random});
    Mockito.when(this.elgamalAlgorithmHelper.decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(BigInteger.TEN.toByteArray());

    int teller = 1;

    final File proofFile = Files.createTempFile(null, null).toFile();
    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    Mockito.when(this.schnorrAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.schnorrAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);
    Mockito.when(this.chaumPedersenAlgorithmHelper.generateProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new Proof());
    Mockito.when(this.chaumPedersenAlgorithmHelper.verifyProof(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);
    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    final ProofWrapper<List<Commitment>> commitmentsWithProof = helper.createCommitments(wrapper, keyPair, keyPairs, shuffledTrackerNumbersWithProof.getObject());

    proofFile.delete();

    teller = 0;

    this.exception.expect(CryptographyException.class);
    helper.decryptCommitments(wrapper, keyPair, teller, keyPairs, trackerNumbersList, Collections.singletonList(commitmentsWithProof.getObject()));
  }

  @Test
  public void testDecryptTrackerNumber() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair encryptionKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));
      final VoterKeyPairs keyPairs = new VoterKeyPairs(encryptionKeyPair, null);
      voterKeyPairs.add(keyPairs);

      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), new byte[i + 1]));
    }

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final BigInteger alpha = BigInteger.ONE;
    final BigInteger beta = BigInteger.TEN;
    final BigInteger publicKey = BigInteger.valueOf(numberOfVoters + 34);

    Mockito.when(this.elgamalAlgorithmHelper.decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(BigInteger.valueOf(0).toByteArray());

    helper.decryptTrackerNumber(wrapper, alpha, beta, publicKey, voterKeyPairs, trackerNumbersList);
  }

  @Test
  public void testDecryptTrackerNumberNoKeyPair() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair encryptionKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));
      final VoterKeyPairs keyPairs = new VoterKeyPairs(encryptionKeyPair, null);
      voterKeyPairs.add(keyPairs);

      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), new byte[i + 1]));
    }

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final BigInteger alpha = null;
    final BigInteger beta = null;
    final BigInteger publicKey = null;

    this.exception.expect(CryptographyException.class);
    helper.decryptTrackerNumber(wrapper, alpha, beta, publicKey, voterKeyPairs, trackerNumbersList);
  }

  @Test
  public void testDecryptTrackerNumberNoTrackerNumberInGroup() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair encryptionKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));
      final VoterKeyPairs keyPairs = new VoterKeyPairs(encryptionKeyPair, null);
      voterKeyPairs.add(keyPairs);

      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), new byte[i + 1]));
    }

    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final BigInteger alpha = BigInteger.ONE;
    final BigInteger beta = BigInteger.TEN;
    final BigInteger publicKey = BigInteger.valueOf(numberOfVoters + 34);

    Mockito.when(this.elgamalAlgorithmHelper.decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(BigInteger.valueOf(numberOfVoters).toByteArray());

    this.exception.expect(CryptographyException.class);
    helper.decryptTrackerNumber(wrapper, alpha, beta, publicKey, voterKeyPairs, trackerNumbersList);
  }

  @Test
  public void testEncryptProof() throws Exception {
    final DSAAlgorithmHelper dsaAlgorithmHelper = new DSAAlgorithmHelper();
    final ElGamalAlgorithmHelper elgamalAlgorithmHelper = new ElGamalAlgorithmHelper();
    final SeleneCryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, dsaAlgorithmHelper, elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createElectionParameters();
    final KeyPair keyPair = helper.createElectionKeyPair(parameters);

    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger random = helper.generateRandom(new SecureRandom(), wrapper.getP());
    final BigInteger plainText = wrapper.getG().modPow(random, wrapper.getP());

    final List<VoterKeyPairs> votersKeyPairs = helper.createVotersKeyPairs(1, wrapper);

    final byte[][] encrypted = elgamalAlgorithmHelper.encrypt(new SecureRandom(), parameters, keyPair, plainText.toByteArray());
    final byte[] signature = dsaAlgorithmHelper.sign(parameters, votersKeyPairs.get(0).getSignatureKeyPair(), encrypted[0]);

    final EncryptProof encryptProof = helper.createEncryptProof(parameters, keyPair, plainText, encrypted[0], votersKeyPairs.get(0).getSignatureKeyPair(),
        signature, new BigInteger(1, encrypted[1]));

    assertThat(helper.verifyEncryptProof(parameters, keyPair, encrypted[0], votersKeyPairs.get(0).getSignatureKeyPair(), encryptProof)).isTrue();
  }

  @Test
  public void testEncryptVotes() throws Exception {
    final ElGamalAlgorithmHelper elgamalHelper = new ElGamalAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) elgamalHelper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = elgamalHelper.createKeys(new SecureRandom(), parameters);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, elgamalHelper, this.verificatumHelper,
        this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final List<Voter> voters = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some null and blank votes.
      final String plainTextVote;

      if ((i > 0) && (i % 5) == 0) {
        plainTextVote = new String(new char[i]).replace('\0', ' ');
      }
      else if ((i > 0) && (i % 7) == 0) {
        plainTextVote = null;
      }
      else {
        plainTextVote = Integer.toString(i);
      }
      voter.setPlainTextVote(plainTextVote);

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(i));

      voterKeyPairs.add(keyPairs);
      voteOptions.add(voteOption);
      voters.add(voter);
    }

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);
    Mockito.when(this.dsaAlgorithmHelper.verify(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ProofWrapper<List<Voter>> votersWithProof = helper.encryptVotes(parameters, keyPair, voterKeyPairs, voteOptions, voters, ersEncryptProofs);
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      assertThat(voter).isNotNull();

      if ((voter.getPlainTextVote() == null) || (voter.getPlainTextVote().trim().length() <= 0)) {
        assertThat(voter.getEncryptedVote()).isNull();
        assertThat(voter.getEncryptedVoteSignature()).isNull();
      }
      else {
        assertThat(voter.getEncryptedVote()).isNotNull();
        assertThat(voter.getEncryptedVoteSignature()).isNotNull();
      }
    }

    votersWithProof.getProofFile().delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testEncryptVotesEncrypted() throws Exception {
    final ElGamalAlgorithmHelper elgamalHelper = new ElGamalAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) elgamalHelper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = elgamalHelper.createKeys(new SecureRandom(), parameters);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, elgamalHelper, this.verificatumHelper,
        this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final List<Voter> voters = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(null, BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some encrypted votes, signatures and proofs.
      final byte[] encryptedVote;
      final byte[] encryptedVoteSignature;
      final EncryptProof encryptProof;

      if ((i > 0) && (i % 7) == 0) {
        encryptedVote = null;
        encryptedVoteSignature = null;
        encryptProof = null;
      }
      else {
        encryptedVote = new byte[] {(byte) i, (byte) i, (byte) i, (byte) i};
        encryptedVoteSignature = new byte[] {(byte) (numberOfVoters + i), (byte) (numberOfVoters + i), (byte) (numberOfVoters + i), (byte) (numberOfVoters + i)};
        encryptProof = new EncryptProof(BigInteger.valueOf(i), BigInteger.valueOf(i), BigInteger.valueOf(i), BigInteger.valueOf(i), encryptedVoteSignature);
      }
      voter.setEncryptedVote(encryptedVote);
      voter.setEncryptedVoteSignature(encryptedVoteSignature);
      ersEncryptProofs.add(encryptProof);

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      voterKeyPairs.add(keyPairs);
      voters.add(voter);
    }

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);
    Mockito.when(this.dsaAlgorithmHelper.verify(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    final ProofWrapper<List<Voter>> votersWithProof = helper.encryptVotes(parameters, keyPair, voterKeyPairs, voteOptions, voters, ersEncryptProofs);
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(numberOfVoters);

    final List<EncryptProof> encryptProofs = (List<EncryptProof>) new BaseShellComponent() {
    }.readCSV(votersWithProof.getProofFile(), EncryptProof.class, JacksonViews.Public.class);

    int j = 0;

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      final EncryptProof encryptProof = encryptProofs.get(j);
      assertThat(voter).isNotNull();

      if ((i > 0) && (i % 7) == 0) {
        assertThat(voter.getEncryptedVote()).isNull();
        assertThat(voter.getEncryptedVoteSignature()).isNull();
      }
      else {
        assertThat(voter.getEncryptedVote()).isNotNull();
        assertThat(voter.getEncryptedVoteSignature()).isNotNull();
        assertThat(encryptProof).isNotNull();
        assertThat(encryptProof.getEncryptedVoteSignature()).isEqualTo(voter.getEncryptedVoteSignature());

        j++;
      }
    }

    assertThat(j).isEqualTo(encryptProofs.size());

    votersWithProof.getProofFile().delete();
  }

  @Test
  public void testEncryptVotesEncryptedMissingProof() throws Exception {
    final ElGamalAlgorithmHelper elgamalHelper = new ElGamalAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) elgamalHelper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = elgamalHelper.createKeys(new SecureRandom(), parameters);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, elgamalHelper, this.verificatumHelper,
        this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final List<Voter> voters = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(null, BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some encrypted votes, signatures and proofs.
      final byte[] encryptedVote;
      final byte[] encryptedVoteSignature;
      final EncryptProof encryptProof = null;

      if ((i > 0) && (i % 7) == 0) {
        encryptedVote = null;
        encryptedVoteSignature = null;
      }
      else {
        encryptedVote = new byte[] {(byte) i, (byte) i, (byte) i, (byte) i};
        encryptedVoteSignature = new byte[] {(byte) (numberOfVoters + i), (byte) (numberOfVoters + i), (byte) (numberOfVoters + i), (byte) (numberOfVoters + i)};
      }
      voter.setEncryptedVote(encryptedVote);
      voter.setEncryptedVoteSignature(encryptedVoteSignature);
      ersEncryptProofs.add(encryptProof);

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      voterKeyPairs.add(keyPairs);
      voters.add(voter);
    }

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);
    Mockito.when(this.dsaAlgorithmHelper.verify(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(true);

    this.exception.expect(CryptographyException.class);
    final ProofWrapper<List<Voter>> votersWithProof = helper.encryptVotes(parameters, keyPair, voterKeyPairs, voteOptions, voters, ersEncryptProofs);

    votersWithProof.getProofFile().delete();
  }

  @Test
  public void testEncryptVotesMissingSignatureKeyPair() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final List<Voter> voters = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some null and blank votes.
      final String plainTextVote;

      if ((i > 0) && (i % 5) == 0) {
        plainTextVote = new String(new char[i]).replace('\0', ' ');
      }
      else if ((i > 0) && (i % 7) == 0) {
        plainTextVote = null;
      }
      else {
        plainTextVote = Integer.toString(i);
      }
      voter.setPlainTextVote(plainTextVote);

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(i));

      voterKeyPairs.add(new VoterKeyPairs(null, null));
      voteOptions.add(voteOption);
      voters.add(voter);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    this.exception.expect(CryptographyException.class);
    helper.encryptVotes(wrapper, keyPair, voterKeyPairs, voteOptions, voters, ersEncryptProofs);
  }

  @Test
  public void testEncryptVotesMissingVoteOption() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> voterKeyPairs = new ArrayList<>();
    final List<Voter> voters = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some null and blank votes.
      final String plainTextVote;

      if ((i > 0) && (i % 5) == 0) {
        plainTextVote = new String(new char[i]).replace('\0', ' ');
      }
      else if ((i > 0) && (i % 7) == 0) {
        plainTextVote = null;
      }
      else {
        plainTextVote = Integer.toString(i);
      }
      voter.setPlainTextVote(plainTextVote);

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(i));

      voterKeyPairs.add(keyPairs);
      voters.add(voter);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    this.exception.expect(CryptographyException.class);
    helper.encryptVotes(wrapper, keyPair, voterKeyPairs, voteOptions, voters, ersEncryptProofs);
  }

  @Test
  public void testEncryptVotesMissingVoterKeyPairs() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<VoterKeyPairs> keyPairs = Arrays.asList(new VoterKeyPairs(null, null), new VoterKeyPairs(null, null));
    final List<Voter> voters = new ArrayList<>();
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = new Voter(i);

      // Throw in some null and blank votes.
      final String plainTextVote;

      if ((i > 0) && (i % 5) == 0) {
        plainTextVote = new String(new char[i]).replace('\0', ' ');
      }
      else if ((i > 0) && (i % 7) == 0) {
        plainTextVote = null;
      }
      else {
        plainTextVote = Integer.toString(i);
      }
      voter.setPlainTextVote(plainTextVote);

      voters.add(voter);
    }

    this.exception.expect(CryptographyException.class);
    helper.encryptVotes(null, null, keyPairs, null, voters, ersEncryptProofs);
  }

  @Test
  public void testEncryptVotesWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<VoterKeyPairs> keyPairs = Arrays.asList(new VoterKeyPairs(null, null), new VoterKeyPairs(null, null));
    final List<Voter> voters = Arrays.asList(new Voter(1), new Voter(2), new Voter(3));
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    this.exception.expect(CryptographyException.class);
    helper.encryptVotes(null, null, keyPairs, null, voters, ersEncryptProofs);
  }

  @Test
  public void testGetTellerInformationFiles() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;
    Mockito.when(this.verificatumHelper.getTellerInformationFiles(Mockito.isNotNull(), Mockito.eq(teller))).thenReturn(new File[wrapper.getNumberOfTellers()]);

    final File[] tellerInformationFiles = helper.getTellerInformationFiles(wrapper, teller);
    assertThat(tellerInformationFiles).isNotNull();
    assertThat(tellerInformationFiles.length).isEqualTo(wrapper.getNumberOfTellers());
  }

  @Test
  public void testGetTellerInformationFilesNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;

    this.exception.expect(CryptographyException.class);
    helper.getTellerInformationFiles(wrapper, teller);
  }

  @Test
  public void testGetTellerInformationFilesWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 0;

    this.exception.expect(CryptographyException.class);
    helper.getTellerInformationFiles(wrapper, teller);
  }

  @Test
  public void testMapVoteOptions() throws Exception {
    final DSAAlgorithmHelper dsaAlgorithmHelper = new DSAAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) dsaAlgorithmHelper.createParameters(new SecureRandom(), 1024, 160, 128);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoteOptions = 100;
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoteOptions; i++) {
      final VoteOption voteOption = new VoteOption(Integer.toString(i));

      if (i == 0) {
        voteOption.setOptionNumberInGroup(BigInteger.TEN);
      }
      voteOptions.add(voteOption);
    }

    helper.mapVoteOptions(parameters, voteOptions);

    for (int i = 0; i < numberOfVoteOptions; i++) {
      assertThat(voteOptions.get(i).getOption()).isEqualTo(Integer.toString(i));

      if (i == 0) {
        assertThat(voteOptions.get(i).getOptionNumberInGroup()).isEqualTo(BigInteger.TEN);
      }
      else {
        assertThat(voteOptions.get(i).getOptionNumberInGroup()).isNotNull();
      }
    }
  }

  @Test
  public void testMapVoteOptionsPreassignedNotUnique() throws Exception {
    final DSAAlgorithmHelper dsaAlgorithmHelper = new DSAAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) dsaAlgorithmHelper.createParameters(new SecureRandom(), 1024, 160, 128);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoteOptions = 100;
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoteOptions; i++) {
      final VoteOption voteOption = new VoteOption(Integer.toString(i));
      voteOption.setOptionNumberInGroup(BigInteger.TEN);
      voteOptions.add(voteOption);
    }

    this.exception.expect(CryptographyException.class);
    helper.mapVoteOptions(parameters, voteOptions);
  }

  @Test
  public void testMergeTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;

    helper.mergeTeller(wrapper, teller);

    Mockito.verify(this.verificatumHelper).mergeTeller(Mockito.isNotNull(), Mockito.eq(teller));
  }

  @Test
  public void testMergeTellerNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 1;

    this.exception.expect(CryptographyException.class);
    helper.mergeTeller(wrapper, teller);
  }

  @Test
  public void testMergeTellerWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int teller = 0;

    this.exception.expect(CryptographyException.class);
    helper.mergeTeller(wrapper, teller);
  }

  @Test
  public void testMixVotes() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    int expectedVoters = 0;
    final List<Voter> voters = new ArrayList<>();
    final List<TrackerNumber> trackerNumbers = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);

      // Throw in some null and blank votes.
      final String plainTextVote;

      if ((i > 0) && (i % 5) == 0) {
        plainTextVote = new String(new char[i]).replace('\0', ' ');
      }
      else if ((i > 0) && (i % 7) == 0) {
        plainTextVote = null;
      }
      else {
        plainTextVote = Integer.toString(i);
      }
      voter.setPlainTextVote(plainTextVote);

      if ((plainTextVote != null) && (plainTextVote.trim().length() > 0)) {
        voter.setEncryptedVote(new CipherText(BigInteger.valueOf(1000 + i), BigInteger.valueOf(1000 + i)).toByteArray());
        expectedVoters++;
      }

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final TrackerNumber trackerNumber = new TrackerNumber(2000 + i, BigInteger.valueOf(2000 + i),
          new CipherText(BigInteger.valueOf(2000 + i), BigInteger.valueOf(2000 + i)).toByteArray());
      voter.setTrackerNumber(trackerNumber);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(1000 + i));

      voteOptions.add(voteOption);
      voters.add(voter);

      trackerNumbers.add(trackerNumber);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    final int teller = 1;

    final File proofFile = Files.createTempFile(null, null).toFile();
    Mockito.doAnswer(invocation -> {
      final List<CipherText> flatCipherTexts = invocation.getArgument(3);
      final List<BigInteger> plainTexts = new ArrayList<>();

      for (final CipherText cipherText : flatCipherTexts) {
        plainTexts.add(cipherText.getAlpha());
      }

      return new ProofWrapper<>(plainTexts, proofFile);
    }).when(this.verificatumHelper).mix(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull());

    final ProofWrapper<List<Voter>> votersWithProof = helper.mixVotes(wrapper, keyPair, teller, trackerNumbers, voteOptions, voters);
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(expectedVoters);

    int numberEqual = 0;

    for (int i = 0; i < votersWithProof.getObject().size(); i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      assertThat(voter.getId()).isNull();
      assertThat(voter.getTrackerNumber().getTrackerNumber()).isNotNull();
      assertThat(voter.getPlainTextVote()).isNotNull();

      final int trackerNumber = voter.getTrackerNumber().getTrackerNumber();
      final String plainTextVote = voter.getPlainTextVote();

      if ((plainTextVote != null) && (plainTextVote.trim().length() > 0)) {
        final Voter found = voters.stream().filter(vote -> plainTextVote.equals(vote.getPlainTextVote())).findAny().orElse(null);
        assertThat(found).isNotNull();
        assertThat(found.getTrackerNumber().getTrackerNumber()).isEqualTo(trackerNumber);
        assertThat(found.getPlainTextVote()).isEqualTo(plainTextVote);
        numberEqual++;
      }
    }

    assertThat(numberEqual).isEqualTo(expectedVoters);

    votersWithProof.getProofFile().delete();
    proofFile.delete();
  }

  @Test
  public void testMixVotesMissingTrackerNumber() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<Voter> voters = new ArrayList<>();
    final List<TrackerNumber> trackerNumbers = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);
      voter.setPlainTextVote(Integer.toString(i));
      voter.setEncryptedVote(new CipherText(BigInteger.valueOf(1000 + i), BigInteger.valueOf(1000 + i)).toByteArray());

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final TrackerNumber trackerNumber = new TrackerNumber(2000 + i, BigInteger.valueOf(2000 + i),
          new CipherText(BigInteger.ZERO, BigInteger.ZERO).toByteArray()); // Rubbish.
      voter.setTrackerNumber(trackerNumber);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(1000 + i));

      voteOptions.add(voteOption);
      voters.add(voter);

      trackerNumbers.add(trackerNumber);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    Mockito.doAnswer(invocation -> {
      final byte[] data = invocation.getArgument(2);
      final CipherText cipherText = new CipherText(data);
      return cipherText.getAlpha().toByteArray();
    }).when(this.elgamalAlgorithmHelper).decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());

    final int teller = 1;

    this.exception.expect(CryptographyException.class);
    helper.mixVotes(wrapper, keyPair, teller, trackerNumbers, voteOptions, voters);
  }

  @Test
  public void testMixVotesMissingVoteOption() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<Voter> voters = new ArrayList<>();
    final List<TrackerNumber> trackerNumbers = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);
      voter.setPlainTextVote(Integer.toString(i));
      voter.setEncryptedVote(new CipherText(BigInteger.valueOf(1000 + i), BigInteger.valueOf(1000 + i)).toByteArray());

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final TrackerNumber trackerNumber = new TrackerNumber(2000 + i, BigInteger.valueOf(2000 + i),
          new CipherText(BigInteger.valueOf(2000 + i), BigInteger.valueOf(2000 + i)).toByteArray());
      voter.setTrackerNumber(trackerNumber);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.ZERO); // Rubbish.

      voteOptions.add(voteOption);
      voters.add(voter);

      trackerNumbers.add(trackerNumber);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    Mockito.doAnswer(invocation -> {
      final byte[] data = invocation.getArgument(2);
      final CipherText cipherText = new CipherText(data);
      return cipherText.getAlpha().toByteArray();
    }).when(this.elgamalAlgorithmHelper).decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());

    final int teller = 1;

    this.exception.expect(CryptographyException.class);
    helper.mixVotes(wrapper, keyPair, teller, trackerNumbers, voteOptions, voters);
  }

  @Test
  public void testMixVotesNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int numberOfVoters = 100;
    final List<Voter> voters = new ArrayList<>();
    final List<TrackerNumber> trackerNumbers = new ArrayList<>();
    final List<VoteOption> voteOptions = new ArrayList<>();
    for (int i = 0; i < numberOfVoters; i++) {
      final KeyPair signatureKeyPair = new KeyPair(BigInteger.valueOf(i), BigInteger.valueOf(numberOfVoters + i));

      final Voter voter = new Voter(i);
      voter.setPlainTextVote(Integer.toString(i));
      voter.setEncryptedVote(new CipherText(BigInteger.valueOf(1000 + i), BigInteger.valueOf(1000 + i)).toByteArray());

      final VoterKeyPairs keyPairs = new VoterKeyPairs(null, signatureKeyPair);
      voter.setVoterKeyPairs(keyPairs);

      final TrackerNumber trackerNumber = new TrackerNumber(2000 + i, BigInteger.valueOf(2000 + i),
          new CipherText(BigInteger.valueOf(2000 + i), BigInteger.valueOf(2000 + i)).toByteArray());
      voter.setTrackerNumber(trackerNumber);

      final VoteOption voteOption = new VoteOption(voter.getPlainTextVote());
      voteOption.setOptionNumberInGroup(BigInteger.valueOf(1000 + i));

      voteOptions.add(voteOption);
      voters.add(voter);

      trackerNumbers.add(trackerNumber);
    }

    final byte[] encrypted = new byte[256];
    final byte[] random = BigInteger.TEN.toByteArray();
    Mockito.when(this.elgamalAlgorithmHelper.encrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new byte[][] {encrypted, random});

    final byte[] signed = new byte[512];
    Mockito.when(this.dsaAlgorithmHelper.sign(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(signed);

    Mockito.doAnswer(invocation -> {
      final byte[] data = invocation.getArgument(2);
      final CipherText cipherText = new CipherText(data);
      return cipherText.getAlpha().toByteArray();
    }).when(this.elgamalAlgorithmHelper).decrypt(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());

    final int teller = 1;

    final ProofWrapper<List<Voter>> votersWithProof = helper.mixVotes(wrapper, keyPair, teller, trackerNumbers, voteOptions, voters);
    assertThat(votersWithProof).isNotNull();
    assertThat(votersWithProof.getProofFile()).isNotNull();
    assertThat(votersWithProof.getObject()).isNotNull();
    assertThat(votersWithProof.getObject().size()).isEqualTo(numberOfVoters);

    int numberEqual = 0;

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = votersWithProof.getObject().get(i);
      assertThat(voter.getId()).isNull();
      assertThat(voter.getTrackerNumber().getTrackerNumber()).isNotNull();
      assertThat(voter.getPlainTextVote()).isNotNull();

      final int trackerNumber = voter.getTrackerNumber().getTrackerNumber();
      final String plainTextVote = voter.getPlainTextVote();

      final Voter found = voters.stream().filter(vote -> vote.getPlainTextVote().equals(plainTextVote)).findAny().orElse(null);
      assertThat(found).isNotNull();
      assertThat(found.getTrackerNumber().getTrackerNumber()).isEqualTo(trackerNumber);
      assertThat(found.getPlainTextVote()).isEqualTo(plainTextVote);
      numberEqual++;
    }

    assertThat(numberEqual).isEqualTo(numberOfVoters);

    votersWithProof.getProofFile().delete();
  }

  @Test
  public void testMixVotesWrongSize() throws Exception {
    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<TrackerNumber> trackerNumbers = Arrays.asList(new TrackerNumber(1, null, null), new TrackerNumber(2, null, null));
    final List<Voter> voters = Arrays.asList(new Voter(), new Voter(), new Voter());

    this.exception.expect(CryptographyException.class);
    helper.mixVotes(null, null, 1, trackerNumbers, null, voters);
  }

  @Test
  public void testMixVotesWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final List<TrackerNumber> trackerNumbers = Arrays.asList(new TrackerNumber(1, null, null), new TrackerNumber(2, null, null));
    final List<Voter> voters = Arrays.asList(new Voter(), new Voter());

    this.exception.expect(CryptographyException.class);
    helper.mixVotes(wrapper, null, 0, trackerNumbers, null, voters);
  }

  @Test
  public void testShuffleTrackerNumbers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    for (int i = 0; i < voters; i++) {
      final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
      cipherTexts.add(cipherText);
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final int teller = 1;
    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final File proofFile = Files.createTempFile(null, null).toFile();
    final ProofWrapper<List<CipherText>> shuffleWithProof = new ProofWrapper<>(cipherTexts, proofFile);
    Mockito.when(this.verificatumHelper.shuffle(Mockito.isNotNull(), Mockito.eq(teller), Mockito.anyInt(), Mockito.isNotNull())).thenReturn(shuffleWithProof);

    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    assertThat(shuffledTrackerNumbersWithProof).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getProofFile()).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getObject()).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getObject().size()).isEqualTo(voters);

    for (int i = 0; i < voters; i++) {
      final TrackerNumber trackerNumber = shuffledTrackerNumbersWithProof.getObject().get(i);
      assertThat(trackerNumber.getTrackerNumber()).isNull();
      assertThat(trackerNumber.getTrackerNumberInGroup()).isNull();
      assertThat(trackerNumber.getEncryptedTrackerNumberInGroup()).isNotEmpty();
    }

    shuffledTrackerNumbersWithProof.getProofFile().delete();
    proofFile.delete();
  }

  @Test
  public void testShuffleTrackerNumbersNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final CipherText cipherText = new CipherText(BigInteger.ONE, BigInteger.TEN);
    for (int i = 0; i < voters; i++) {
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), cipherText.toByteArray()));
    }

    final int teller = 1;
    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
    assertThat(shuffledTrackerNumbersWithProof).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getProofFile()).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getObject()).isNotNull();
    assertThat(shuffledTrackerNumbersWithProof.getObject().size()).isEqualTo(voters);

    int numberEqual = 0;

    for (int i = 0; i < voters; i++) {
      final TrackerNumber trackerNumber = shuffledTrackerNumbersWithProof.getObject().get(i);
      assertThat(trackerNumber.getTrackerNumber()).isNull();
      assertThat(trackerNumber.getTrackerNumberInGroup()).isNull();
      assertThat(trackerNumber.getEncryptedTrackerNumberInGroup()).isNotEmpty();

      if (Arrays.equals(trackerNumber.getEncryptedTrackerNumberInGroup(), trackerNumbersList.get(i).getEncryptedTrackerNumberInGroup())) {
        numberEqual++;
      }
    }

    assertThat(numberEqual).isEqualTo(voters);

    shuffledTrackerNumbersWithProof.getProofFile().delete();
  }

  @Test
  public void testShuffleTrackerNumbersWrongTeller() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper wrapper = new DHParametersWrapper(object);
    wrapper.setNumberOfTellers(4);
    wrapper.setThresholdTellers(3);

    final CryptographyHelper helper = new SeleneCryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();

    final int voters = 100;
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    for (int i = 0; i < voters; i++) {
      trackerNumbers.add(new TrackerNumber(i, BigInteger.valueOf(i), new byte[i + 1]));
    }

    final int teller = 0;
    final ArrayList<TrackerNumber> trackerNumbersList = new ArrayList<>(trackerNumbers);

    this.exception.expect(CryptographyException.class);
    helper.shuffleTrackerNumbers(wrapper, teller, trackerNumbersList);
  }
}
