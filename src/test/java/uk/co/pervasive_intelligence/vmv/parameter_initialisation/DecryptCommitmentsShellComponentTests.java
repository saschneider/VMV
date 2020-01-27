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
import java.nio.file.Files;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Decrypt commitments tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class DecryptCommitmentsShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File commitmentsProofs = new File("commitments-proofs.csv");

  private final File decryptProofs = new File("decrypt-proofs.zip");

  private final File outputCommitments = new File("commitments.csv");

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishCommitments = new File("public-commitments.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishTrackerNumbers = new File("public-tracker-numbers.csv");

  private final File publishVoters = new File("publish-voters.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  private final File shuffleProofs = new File("shuffle-proofs.zip");

  private final File shuffledTrackerNumbers = new File("shuffled-tracker-numbers.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

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
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateCommitments() throws Exception {
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

    final Set<TrackerNumber> trackerNumbers = new HashSet<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final TrackerNumber trackerNumber = new TrackerNumber(i + 1, BigInteger.ZERO, new byte[10]);
      trackerNumbers.add(trackerNumber);
    }

    Mockito.when(this.cryptographyHelper.createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt())).thenReturn(trackerNumbers);

    final CreateTrackerNumbersShellComponent createTrackerNumbersShellComponent = new CreateTrackerNumbersShellComponent(this.cryptographyHelper);
    final CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions createTrackerNumbersOptions =
        new CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions(Arrays.asList(this.publishParams, this.publishKeys), numberOfVoters,
            this.publishTrackerNumbers);
    createTrackerNumbersShellComponent.createTrackerNumbers(createTrackerNumbersOptions);

    final int teller = 1;
    final List<TrackerNumber> shuffledTrackerNumbers = new ArrayList<>(trackerNumbers);
    final File shuffleProofFile = Files.createTempFile(null, null).toFile();
    Mockito.when(this.cryptographyHelper.shuffleTrackerNumbers(Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(shuffledTrackerNumbers, shuffleProofFile));

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

    final File commitmentsProofFile = Files.createTempFile(null, null).toFile();
    Mockito.when(this.cryptographyHelper.createCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(commitments, commitmentsProofFile));

    final CreateCommitmentsShellComponent createCommitmentsShellComponent = new CreateCommitmentsShellComponent(this.cryptographyHelper);
    final CreateCommitmentsShellComponent.CreateCommitmentsOptions createCommitmentsOptions =
        new CreateCommitmentsShellComponent.CreateCommitmentsOptions(Arrays.asList(this.publishParams, this.publishKeys), this.publishVotersKeys,
            this.shuffledTrackerNumbers, this.outputCommitments, Arrays.asList(this.publishCommitments, this.commitmentsProofs));
    createCommitmentsShellComponent.createCommitments(createCommitmentsOptions);

    final List<Voter> voters = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      voters.add(new Voter(i));
    }

    final File decryptProofFile = Files.createTempFile(null, null).toFile();
    Mockito.when(this.cryptographyHelper.decryptCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(),
        Mockito.isNotNull(), Mockito.isNotNull())).thenReturn(new ProofWrapper<>(voters, decryptProofFile));

    final DecryptCommitmentsShellComponent decryptCommitmentsShellComponent = new DecryptCommitmentsShellComponent(this.cryptographyHelper);
    assertThat(decryptCommitmentsShellComponent).isNotNull();

    assertThat(this.publishVoters.exists()).isFalse();
    assertThat(this.decryptProofs.exists()).isFalse();

    final DecryptCommitmentsShellComponent.DecryptCommitmentsOptions decryptCommitmentsOptions =
        new DecryptCommitmentsShellComponent.DecryptCommitmentsOptions(Arrays.asList(this.publishParams, this.outputKeys), teller, this.publishVotersKeys,
            this.shuffledTrackerNumbers, Collections.singletonList(this.publishCommitments), Arrays.asList(this.publishVoters, this.decryptProofs));
    decryptCommitmentsShellComponent.decryptCommitments(decryptCommitmentsOptions);

    assertThat(this.publishVoters.exists()).isTrue();
    assertThat(this.decryptProofs.exists()).isTrue();

    final List<Voter> publishVoters = (List<Voter>) decryptCommitmentsShellComponent.readCSV(this.publishVoters, Voter.class, JacksonViews.Public.class);
    assertThat(publishVoters).isNotNull();
    assertThat(publishVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publishVoters.get(i).getId()).isNull();
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(6)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).shuffleTrackerNumbers(Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).createCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).decryptCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(),
        Mockito.isNotNull(), Mockito.isNotNull());

    shuffleProofFile.delete();
    commitmentsProofFile.delete();
    decryptProofFile.delete();
  }
}
