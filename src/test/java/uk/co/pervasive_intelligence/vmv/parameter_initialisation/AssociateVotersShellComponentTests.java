/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.parameter_initialisation;

import org.bouncycastle.crypto.params.DHParameters;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.io.File;
import java.math.BigInteger;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Associate voter tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class AssociateVotersShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File commitmentsProofs = new File("commitments-proofs.csv");

  private final File decryptProofs = new File("decrypt-proofs.zip");

  private final File ersAssociatedVoters = new File("ers-associated-voters.csv");

  private final File ersVoters = new File("ers-voters.csv");

  private final File outputCommitments = new File("output-commitments.csv");

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishAssociatedVoters = new File("public-associated-voters.csv");

  private final File publishCommitments = new File("publish-commitments.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishTrackerNumbers = new File("public-tracker-numbers.csv");

  private final File publishVoters = new File("publish-voters.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  private final File shuffleProofs = new File("shuffle-proofs.zip");

  private final File shuffledTrackerNumbers = new File("shuffled-tracker-numbers.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @SuppressWarnings("unchecked")
  public void runAssociateVoter(final Class<?> ersFileClazz) throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.cryptographyHelper.createElectionKeyPair(Mockito.notNull(), Mockito.anyInt())).thenReturn(keyPair);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    final CreateElectionParametersShellComponent.CreateElectionParametersOptions createElectionParametersOptions =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", true, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(createElectionParametersOptions);

    Mockito.<Class<?>>when(this.cryptographyHelper.getElectionParametersClass()).thenReturn(parameters.getClass());

    final CreateElectionKeysShellComponent createElectionKeysShellComponent = new CreateElectionKeysShellComponent(this.cryptographyHelper);
    final CreateElectionKeysShellComponent.CreateElectionKeysOptions createElectionKeysOptions =
        new CreateElectionKeysShellComponent.CreateElectionKeysOptions(this.publishParams, 0, this.outputKeys, this.publishKeys);
    createElectionKeysShellComponent.createElectionKeys(createElectionKeysOptions);

    assertThat(this.outputVotersKeys.exists()).isFalse();
    assertThat(this.publishVotersKeys.exists()).isFalse();

    final CreateVotersKeysShellComponent createVotersKeysShellComponent = new CreateVotersKeysShellComponent(this.cryptographyHelper);
    assertThat(createVotersKeysShellComponent).isNotNull();

    final int numberOfVoters = 10;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      keyPairs.add(new VoterKeyPairs(
          new KeyPair(BigInteger.valueOf(i + 1), BigInteger.valueOf(i + 2)), new KeyPair(BigInteger.valueOf(i + 3), BigInteger.valueOf(i + 4))));
    }

    Mockito.when(this.cryptographyHelper.createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull())).thenReturn(keyPairs);

    final CreateVotersKeysShellComponent.CreateVotersKeysOptions createVotersKeysOptions =
        new CreateVotersKeysShellComponent.CreateVotersKeysOptions(this.publishParams, numberOfVoters, this.outputVotersKeys, this.publishVotersKeys);
    createVotersKeysShellComponent.createVotersKeys(createVotersKeysOptions);

    final AssociateVotersShellComponent associateVotersShellComponent = new AssociateVotersShellComponent(this.cryptographyHelper);
    assertThat(associateVotersShellComponent).isNotNull();

    final List<Voter> ersVoters = new ArrayList<>();
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = new Voter(i);

      if ((i == 0) || (i == (numberOfVoters - 1))) {
        final KeyPair trapdoorKeyPair = new KeyPair(null, BigInteger.valueOf(100 + i));
        final KeyPair signatureKeyPair = new KeyPair(null, BigInteger.valueOf(200 + i));
        final VoterKeyPairs voterKeyPairs = new VoterKeyPairs(trapdoorKeyPair, signatureKeyPair);
        voter.setVoterKeyPairs(voterKeyPairs);
      }

      ersVoters.add(voter);

      final TrackerNumber trackerNumber = new TrackerNumber(i + 1, BigInteger.ZERO, new byte[10]);
      trackerNumbers.add(trackerNumber);
    }

    associateVotersShellComponent.writeCSV(this.ersVoters, Voter.class, ersVoters, ersFileClazz);

    Mockito.when(this.cryptographyHelper.createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt())).thenReturn(trackerNumbers);

    final CreateTrackerNumbersShellComponent createTrackerNumbersShellComponent = new CreateTrackerNumbersShellComponent(this.cryptographyHelper);
    final CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions createTrackerNumbersOptions =
        new CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions(Arrays.asList(this.publishParams, this.publishKeys), numberOfVoters,
            this.publishTrackerNumbers);
    createTrackerNumbersShellComponent.createTrackerNumbers(createTrackerNumbersOptions);

    final int teller = 1;
    final List<TrackerNumber> shuffledTrackerNumbers = new ArrayList<>(trackerNumbers);
    Mockito.when(this.cryptographyHelper.shuffleTrackerNumbers(Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(shuffledTrackerNumbers, null));

    final ShuffleTrackerNumbersShellComponent shuffleTrackerNumbersShellComponent = new ShuffleTrackerNumbersShellComponent(this.cryptographyHelper);
    final ShuffleTrackerNumbersShellComponent.ShuffleTrackerNumbersOptions shuffleTrackerNumbersOptions =
        new ShuffleTrackerNumbersShellComponent.ShuffleTrackerNumbersOptions(this.publishParams, teller, this.publishTrackerNumbers,
            Arrays.asList(this.shuffledTrackerNumbers, this.shuffleProofs));
    shuffleTrackerNumbersShellComponent.shuffleTrackerNumbers(shuffleTrackerNumbersOptions);

    final List<Commitment> commitments = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Commitment commitment = new Commitment();
      commitment.setEncryptedG(new byte[2]);
      commitment.setEncryptedH(new byte[3]);
      commitments.add(commitment);
    }

    Mockito.when(this.cryptographyHelper.createCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(commitments, null));

    final CreateCommitmentsShellComponent createCommitmentsShellComponent = new CreateCommitmentsShellComponent(this.cryptographyHelper);
    final CreateCommitmentsShellComponent.CreateCommitmentsOptions createCommitmentsOptions =
        new CreateCommitmentsShellComponent.CreateCommitmentsOptions(Arrays.asList(this.publishParams, this.publishKeys), this.publishVotersKeys,
            this.shuffledTrackerNumbers, this.outputCommitments, Arrays.asList(this.publishCommitments, this.commitmentsProofs));
    createCommitmentsShellComponent.createCommitments(createCommitmentsOptions);

    final List<Voter> voters = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      voters.add(new Voter(i));
    }

    Mockito.when(this.cryptographyHelper.decryptCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(),
        Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(voters, null));

    final DecryptCommitmentsShellComponent decryptCommitmentsShellComponent = new DecryptCommitmentsShellComponent(this.cryptographyHelper);
    final DecryptCommitmentsShellComponent.DecryptCommitmentsOptions decryptCommitmentsOptions =
        new DecryptCommitmentsShellComponent.DecryptCommitmentsOptions(Arrays.asList(this.publishParams, this.outputKeys), teller, this.publishVotersKeys,
            this.shuffledTrackerNumbers, Collections.singletonList(this.publishCommitments), Arrays.asList(this.publishVoters, this.decryptProofs));
    decryptCommitmentsShellComponent.decryptCommitments(decryptCommitmentsOptions);

    Mockito.doAnswer(invocation -> {
      List<Voter> source = invocation.getArgument(0);
      List<Voter> destination = invocation.getArgument(1);

      for (int i = 0; i < source.size(); i++) {
        destination.get(i).setId(source.get(i).getId());
      }

      return null;
    }).when(this.cryptographyHelper).associateVoters(Mockito.isNotNull(), Mockito.isNotNull());

    assertThat(this.ersAssociatedVoters.exists()).isFalse();
    assertThat(this.publishAssociatedVoters.exists()).isFalse();

    final AssociateVotersShellComponent.AssociateVotersOptions associateVotersOptions =
        new AssociateVotersShellComponent.AssociateVotersOptions(Arrays.asList(this.publishParams, this.publishKeys), Arrays.asList(this.publishVoters,
            this.ersVoters), this.ersAssociatedVoters, this.publishAssociatedVoters);
    associateVotersShellComponent.associateVoters(associateVotersOptions);

    assertThat(this.ersAssociatedVoters.exists()).isTrue();
    assertThat(this.publishAssociatedVoters.exists()).isTrue();

    final List<Voter> ersAssociatedVoters = (List<Voter>) associateVotersShellComponent.readCSV(this.ersAssociatedVoters, Voter.class,
        JacksonViews.ERSExport.class);
    assertThat(ersAssociatedVoters).isNotNull();
    assertThat(ersAssociatedVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(ersAssociatedVoters.get(i).getId()).isEqualTo(i);
    }

    final List<Voter> publisAssociatedVoters = (List<Voter>) associateVotersShellComponent.readCSV(this.publishAssociatedVoters, Voter.class,
        JacksonViews.Public.class);
    assertThat(publisAssociatedVoters).isNotNull();
    assertThat(publisAssociatedVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publisAssociatedVoters.get(i).getId()).isNull();
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(7)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).shuffleTrackerNumbers(Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).createCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).decryptCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(),
        Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).associateVoters(Mockito.isNotNull(), Mockito.isNotNull());
  }

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
    this.outputKeys.delete();
    this.publishKeys.delete();

    this.outputVotersKeys.delete();
    this.publishVotersKeys.delete();

    this.publishTrackerNumbers.delete();

    this.shuffledTrackerNumbers.delete();
    this.shuffleProofs.delete();

    this.outputCommitments.delete();
    this.publishCommitments.delete();
    this.commitmentsProofs.delete();

    this.publishVoters.delete();
    this.decryptProofs.delete();

    this.ersVoters.delete();
    this.ersAssociatedVoters.delete();
    this.publishAssociatedVoters.delete();
  }

  @Test
  public void testAssociateVoterIDs() throws Exception {
    this.runAssociateVoter(JacksonViews.ERSImport.class);
  }

  @Test
  public void testAssociateVoterIDsKeys() throws Exception {
    this.runAssociateVoter(JacksonViews.ERSKeyImport.class);
  }
}
