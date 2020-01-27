/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.vote_anonymisation_and_decryption;

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
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.CreateElectionKeysShellComponent;
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.CreateElectionParametersShellComponent;
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.CreateVotersKeysShellComponent;
import uk.co.pervasive_intelligence.vmv.vote_encryption.EncryptVotesShellComponent;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Mix votes tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class MixVotesShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File encryptProofs = new File("encrypt-proofs.csv");

  private final File ersEncryptedVoters = new File("ers-encrypted-voters.csv");

  private final File ersPlainTextVoters = new File("ers-plaintext-voters.csv");

  private final File ersVoteOptions = new File("ers-vote-options.csv");

  private final File mixProofs = new File("mix-proofs.zip");

  private final File outputCommitments = new File("commitments.csv");

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishEncryptedVoters = new File("public-encrypted-voters.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishMixedVoters = new File("public-mixed-votes.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishTrackerNumbers = new File("public-tracker-numbers.csv");

  private final File publishVoteOptions = new File("public-vote-options.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
    this.outputKeys.delete();
    this.publishKeys.delete();

    this.outputCommitments.delete();

    this.outputVotersKeys.delete();
    this.publishVotersKeys.delete();

    this.ersPlainTextVoters.delete();
    this.ersVoteOptions.delete();
    this.ersEncryptedVoters.delete();
    this.publishTrackerNumbers.delete();
    this.publishEncryptedVoters.delete();
    this.publishVoteOptions.delete();

    this.encryptProofs.delete();

    this.publishMixedVoters.delete();
    this.mixProofs.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testMixVotes() throws Exception {
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

    final int numberOfVoters = 10;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      keyPairs.add(new VoterKeyPairs(
          new KeyPair(BigInteger.valueOf(i + 1), BigInteger.valueOf(i + 2)), new KeyPair(BigInteger.valueOf(i + 3), BigInteger.valueOf(i + 4))));
    }

    Mockito.when(this.cryptographyHelper.createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull())).thenReturn(keyPairs);

    final CreateVotersKeysShellComponent createVotersKeysShellComponent = new CreateVotersKeysShellComponent(this.cryptographyHelper);
    final CreateVotersKeysShellComponent.CreateVotersKeysOptions createVotersKeysOptions =
        new CreateVotersKeysShellComponent.CreateVotersKeysOptions(this.publishParams, numberOfVoters, this.outputVotersKeys, this.publishVotersKeys);
    createVotersKeysShellComponent.createVotersKeys(createVotersKeysOptions);

    final EncryptVotesShellComponent encryptVotesShellComponent = new EncryptVotesShellComponent(this.cryptographyHelper);
    assertThat(encryptVotesShellComponent).isNotNull();

    final List<Voter> ersPlainTextVoters = new ArrayList<>();
    final List<Voter> mixedVoters = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = new Voter(i);
      voter.setVoterKeyPairs(keyPairs.get(i));
      voter.setTrackerNumber(new TrackerNumber(i + 1, BigInteger.ZERO, new byte[10]));
      voter.setPlainTextVote("Test Vote");
      ersPlainTextVoters.add(voter);
      mixedVoters.add(voter);
    }

    encryptVotesShellComponent.writeCSV(this.ersPlainTextVoters, Voter.class, ersPlainTextVoters, JacksonViews.ERSVoteImport.class);
    encryptVotesShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, Arrays.asList(new VoteOption("Yes"), new VoteOption("No")),
        JacksonViews.ERSImport.class);

    final List<Commitment> commitments = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Commitment commitment = new Commitment();
      commitment.setEncryptedG(new byte[2]);
      commitment.setEncryptedH(new byte[3]);
      commitments.add(commitment);
    }

    encryptVotesShellComponent.writeCSV(this.outputCommitments, Commitment.class, commitments);

    Mockito.doAnswer(invocation -> {
      List<VoteOption> voterOptions = invocation.getArgument(1);

      for (int i = 0; i < voterOptions.size(); i++) {
        voterOptions.get(i).setOptionNumberInGroup(BigInteger.valueOf(i));
      }

      return null;
    }).when(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());

    final File encryptProofFile = Files.createTempFile(null, null).toFile();
    Mockito.doAnswer(invocation -> {
      List<Voter> voters = invocation.getArgument(4);

      for (int i = 0; i < voters.size(); i++) {
        voters.get(i).setEncryptedVote(new byte[i + 1]);
        voters.get(i).setEncryptedVoteSignature(new byte[i + 1 + voters.size()]);
      }

      return new ProofWrapper<>(voters, encryptProofFile);
    }).when(this.cryptographyHelper).encryptVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.any());

    final EncryptVotesShellComponent.EncryptVotesOptions encryptVotesOptions =
        new EncryptVotesShellComponent.EncryptVotesOptions(Arrays.asList(this.publishParams, this.publishKeys),
            Arrays.asList(this.outputVotersKeys, this.ersPlainTextVoters), this.ersVoteOptions, Collections.singletonList(this.outputCommitments),
            this.ersEncryptedVoters, Arrays.asList(this.publishEncryptedVoters, this.publishVoteOptions, this.encryptProofs));
    encryptVotesShellComponent.encryptVotes(encryptVotesOptions);

    final List<TrackerNumber> trackerNumbers = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final TrackerNumber trackerNumber = new TrackerNumber(i + 1, BigInteger.valueOf(i + 1), new byte[10]);
      trackerNumbers.add(trackerNumber);
    }

    encryptVotesShellComponent.writeCSV(this.publishTrackerNumbers, TrackerNumber.class, trackerNumbers, JacksonViews.RestrictedPublic.class);

    final int teller = 1;

    final File mixProofFile = Files.createTempFile(null, null).toFile();
    Mockito.when(this.cryptographyHelper.mixVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull())).thenReturn(new ProofWrapper<>(mixedVoters, mixProofFile));

    assertThat(this.publishMixedVoters.exists()).isFalse();
    assertThat(this.mixProofs.exists()).isFalse();

    final MixVotesShellComponent mixVotesShellComponent = new MixVotesShellComponent(this.cryptographyHelper);
    assertThat(mixVotesShellComponent).isNotNull();

    final MixVotesShellComponent.MixVotesOptions mixVotesOptions = new MixVotesShellComponent.MixVotesOptions(Arrays.asList(this.publishParams, this.outputKeys),
        teller, this.publishTrackerNumbers, this.publishVoteOptions, this.publishEncryptedVoters, Arrays.asList(this.publishMixedVoters, this.mixProofs));
    mixVotesShellComponent.mixVotes(mixVotesOptions);

    assertThat(this.publishMixedVoters.exists()).isTrue();
    assertThat(this.mixProofs.exists()).isTrue();

    final List<Voter> publishMixedVoters = (List<Voter>) encryptVotesShellComponent.readCSV(this.publishMixedVoters, Voter.class, JacksonViews.Mixed.class);
    assertThat(publishMixedVoters).isNotNull();
    assertThat(publishMixedVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publishMixedVoters.get(i).getTrackerNumber().getTrackerNumber()).isNotNull();
      assertThat(publishMixedVoters.get(i).getPlainTextVote()).isNotNull();
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(4)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).encryptVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.any());
    Mockito.verify(this.cryptographyHelper).mixVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.eq(teller), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull());

    encryptProofFile.delete();
    mixProofFile.delete();
  }
}
