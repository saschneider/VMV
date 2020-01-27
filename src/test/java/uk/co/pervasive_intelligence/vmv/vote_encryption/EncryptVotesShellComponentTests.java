/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.vote_encryption;

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

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Encrypt votes tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class EncryptVotesShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File encryptProofs = new File("encrypt-proofs.csv");

  private final File ersEncryptProofs = new File("ers-encrypt-proofs.csv");

  private final File ersEncryptedVoters = new File("ers-encrypted-voters.csv");

  private final File ersPlainTextVoters = new File("ers-plaintext-voters.csv");

  private final File ersVoteOptions = new File("ers-vote-options.csv");

  private final File outputCommitments = new File("commitments.csv");

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishEncryptedVoters = new File("public-encrypted-voters.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishVoteOptions = new File("public-vote-options.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @SuppressWarnings("unchecked")
  public void runEncryptVotes(final Class<?> ersFileClazz, final boolean votersKeys) throws Exception {
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
    final List<EncryptProof> ersEncryptProofs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      final Voter voter = new Voter(i);
      voter.setVoterKeyPairs(keyPairs.get(i));
      voter.setTrackerNumber(new TrackerNumber(i + 1, BigInteger.ZERO, new byte[10]));
      voter.setPlainTextVote("Yes");
      voter.setEncryptedVote(new byte[] {1, 2, 3, 4});

      if (!votersKeys) {
        voter.setEncryptedVoteSignature(new byte[] {5, 6, 7, 8});
        voter.setBeta(BigInteger.valueOf((1000 + i)));
        ersEncryptProofs.add(new EncryptProof(BigInteger.valueOf(i), BigInteger.valueOf(i), BigInteger.valueOf(i), BigInteger.valueOf(i),
            voter.getEncryptedVoteSignature()));
      }

      ersPlainTextVoters.add(voter);
    }

    final List<VoteOption> voteOptions = Arrays.asList(new VoteOption("Yes"), new VoteOption("No"));

    encryptVotesShellComponent.writeCSV(this.ersPlainTextVoters, Voter.class, ersPlainTextVoters, ersFileClazz);
    encryptVotesShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, voteOptions, JacksonViews.ERSImport.class);
    encryptVotesShellComponent.writeCSV(this.ersEncryptProofs, EncryptProof.class, ersEncryptProofs, JacksonViews.Public.class);

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
      List<VoterKeyPairs> votersKeyPairs = invocation.getArgument(2);
      List<Voter> voters = invocation.getArgument(4);

      for (int i = 0; i < voters.size(); i++) {
        if (votersKeyPairs.get(i).getTrapdoorKeyPair().getPublicKey() != null) {
          voters.get(i).setEncryptedVote(new byte[i + 1]);
        }
        if (votersKeyPairs.get(i).getSignatureKeyPair().getPrivateKey() != null) {
          voters.get(i).setEncryptedVoteSignature(new byte[i + 1 + voters.size()]);
        }
      }

      return new ProofWrapper<>(voters, encryptProofFile);
    }).when(this.cryptographyHelper).encryptVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.any());

    Mockito.doAnswer(invocation -> {
      List<Voter> voters = invocation.getArgument(1);

      for (Voter voter : voters) {
        voter.setAlpha(BigInteger.TEN);
      }

      return null;
    }).when(this.cryptographyHelper).completeCommitments(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull());

    assertThat(this.ersEncryptedVoters.exists()).isFalse();
    assertThat(this.publishEncryptedVoters.exists()).isFalse();
    assertThat(this.publishVoteOptions.exists()).isFalse();

    final EncryptVotesShellComponent.EncryptVotesOptions encryptVotesOptions;

    if (votersKeys) {
      encryptVotesOptions =
          new EncryptVotesShellComponent.EncryptVotesOptions(Arrays.asList(this.publishParams, this.publishKeys),
              Arrays.asList(this.outputVotersKeys, this.ersPlainTextVoters, this.ersEncryptProofs), this.ersVoteOptions,
              Collections.singletonList(this.outputCommitments),
              this.ersEncryptedVoters, Arrays.asList(this.publishEncryptedVoters, this.publishVoteOptions, this.encryptProofs));
    }
    else {
      encryptVotesOptions =
          new EncryptVotesShellComponent.EncryptVotesOptions(Arrays.asList(this.publishParams, this.publishKeys),
              Collections.singletonList(this.ersPlainTextVoters), this.ersVoteOptions, Collections.singletonList(this.outputCommitments),
              this.ersEncryptedVoters, Arrays.asList(this.publishEncryptedVoters, this.publishVoteOptions, this.encryptProofs));
    }
    encryptVotesShellComponent.encryptVotes(encryptVotesOptions);

    assertThat(this.ersEncryptedVoters.exists()).isTrue();
    assertThat(this.publishEncryptedVoters.exists()).isTrue();
    assertThat(this.publishVoteOptions.exists()).isTrue();

    final List<Voter> ersEncryptedVoters = (List<Voter>) encryptVotesShellComponent.readCSV(this.ersEncryptedVoters, Voter.class, JacksonViews.ERSVoteExport.class);
    assertThat(ersEncryptedVoters).isNotNull();
    assertThat(ersEncryptedVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(ersEncryptedVoters.get(i).getId()).isEqualTo(i);
      assertThat(ersEncryptedVoters.get(i).getAlpha()).isNotNull();
      assertThat(ersEncryptedVoters.get(i).getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
      assertThat(ersEncryptedVoters.get(i).getEncryptedVote()).isNotNull();
      assertThat(ersEncryptedVoters.get(i).getEncryptedVoteSignature()).isNotNull();
    }

    final List<Voter> publishEncryptedVoters = (List<Voter>) encryptVotesShellComponent.readCSV(this.publishEncryptedVoters, Voter.class, JacksonViews.Vote.class);
    assertThat(publishEncryptedVoters).isNotNull();
    assertThat(publishEncryptedVoters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publishEncryptedVoters.get(i).getId()).isNull();
      assertThat(publishEncryptedVoters.get(i).getAlpha()).isNull();
      assertThat(publishEncryptedVoters.get(i).getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNotNull();
      assertThat(publishEncryptedVoters.get(i).getEncryptedVote()).isNotNull();
      assertThat(publishEncryptedVoters.get(i).getEncryptedVoteSignature()).isNotNull();
    }

    final List<VoteOption> publishVoteOptions = (List<VoteOption>) encryptVotesShellComponent.readCSV(this.publishVoteOptions, VoteOption.class,
        JacksonViews.Public.class);
    assertThat(publishVoteOptions).isNotNull();
    assertThat(publishVoteOptions.size()).isEqualTo(voteOptions.size());

    for (int i = 0; i < voteOptions.size(); i++) {
      assertThat(publishVoteOptions.get(i).getOption()).isNotNull();
      assertThat(publishVoteOptions.get(i).getOptionNumberInGroup()).isNotNull();
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(3)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).encryptVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.any());

    encryptProofFile.delete();
  }

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
    this.ersEncryptProofs.delete();
    this.ersEncryptedVoters.delete();
    this.publishEncryptedVoters.delete();
    this.publishVoteOptions.delete();

    this.encryptProofs.delete();
  }

  @Test
  public void testEncryptVotesEncrypted() throws Exception {
    this.runEncryptVotes(JacksonViews.ERSVoteEncryptedImport.class, false);
  }

  @Test
  public void testEncryptVotesPlaintext() throws Exception {
    this.runEncryptVotes(JacksonViews.ERSVoteImport.class, true);
  }
}
