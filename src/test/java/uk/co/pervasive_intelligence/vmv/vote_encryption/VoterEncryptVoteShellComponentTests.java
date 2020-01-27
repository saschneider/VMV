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
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.MapVoteOptionsShellComponent;
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.VoterCreateKeysShellComponent;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Voter encrypt vote tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class VoterEncryptVoteShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File encryptProofs = new File("encrypt-proofs.csv");

  private final File ersVoteOptions = new File("ers-vote-options.csv");

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishEncryptedVoters = new File("public-encrypted-voters.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

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

    this.outputVotersKeys.delete();
    this.publishVotersKeys.delete();

    this.ersVoteOptions.delete();
    this.publishVoteOptions.delete();

    this.publishEncryptedVoters.delete();
    this.encryptProofs.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testVoterEncryptVote() throws Exception {
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

    final VoterCreateKeysShellComponent voterCreateKeysShellComponent = new VoterCreateKeysShellComponent(this.cryptographyHelper);
    assertThat(voterCreateKeysShellComponent).isNotNull();

    final int numberOfVoters = 1;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      keyPairs.add(new VoterKeyPairs(
          new KeyPair(BigInteger.valueOf(i + 1), BigInteger.valueOf(i + 2)), new KeyPair(BigInteger.valueOf(i + 3), BigInteger.valueOf(i + 4))));
    }

    Mockito.when(this.cryptographyHelper.createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull())).thenReturn(keyPairs);

    final VoterCreateKeysShellComponent.VoterCreateKeysOptions voterCreateKeysOptions =
        new VoterCreateKeysShellComponent.VoterCreateKeysOptions(this.publishParams, this.outputVotersKeys, this.publishVotersKeys);
    voterCreateKeysShellComponent.voterCreateKeys(voterCreateKeysOptions);

    final MapVoteOptionsShellComponent mapVoteOptionsShellComponent = new MapVoteOptionsShellComponent(this.cryptographyHelper);

    final int numberOfVoteOptions = 100;
    final List<VoteOption> ersVoteOptions = new ArrayList<>();

    for (int i = 0; i < numberOfVoteOptions; i++) {
      final VoteOption voteOption = new VoteOption(Integer.toString(numberOfVoteOptions + i));
      ersVoteOptions.add(voteOption);
    }

    final String plainTextVote = ersVoteOptions.get(0).getOption();

    mapVoteOptionsShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, ersVoteOptions, JacksonViews.ERSImport.class);

    Mockito.doAnswer(invocation -> {
      List<VoteOption> voterOptions = invocation.getArgument(1);

      for (int i = 0; i < voterOptions.size(); i++) {
        voterOptions.get(i).setOptionNumberInGroup(BigInteger.valueOf(i));
      }

      return null;
    }).when(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());

    final MapVoteOptionsShellComponent.MapVoteOptionsOptions mapVoteOptionsOptions =
        new MapVoteOptionsShellComponent.MapVoteOptionsOptions(this.publishParams, this.ersVoteOptions, this.publishVoteOptions);
    mapVoteOptionsShellComponent.mapVoteOptions(mapVoteOptionsOptions);

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

    assertThat(this.publishEncryptedVoters.exists()).isFalse();
    assertThat(this.encryptProofs.exists()).isFalse();

    final VoterEncryptVoteShellComponent voterEncryptVoteShellComponent = new VoterEncryptVoteShellComponent(this.cryptographyHelper);
    assertThat(voterEncryptVoteShellComponent).isNotNull();

    final VoterEncryptVoteShellComponent.VoterEncryptVoteOptions voterEncryptVoteOptions =
        new VoterEncryptVoteShellComponent.VoterEncryptVoteOptions(Collections.singletonList(plainTextVote), Arrays.asList(this.publishParams, this.publishKeys),
            this.outputVotersKeys, this.publishVoteOptions, Arrays.asList(this.publishEncryptedVoters, this.encryptProofs));
    voterEncryptVoteShellComponent.voterEncryptVote(voterEncryptVoteOptions);

    assertThat(this.publishEncryptedVoters.exists()).isTrue();
    assertThat(this.encryptProofs.exists()).isTrue();

    final List<Voter> publishEncryptedVoters = (List<Voter>) voterEncryptVoteShellComponent.readCSV(this.publishEncryptedVoters, Voter.class,
        JacksonViews.VoterVote.class);
    assertThat(publishEncryptedVoters).isNotNull();
    assertThat(publishEncryptedVoters.size()).isEqualTo(1);

    assertThat(publishEncryptedVoters.get(0).getId()).isNull();
    assertThat(publishEncryptedVoters.get(0).getAlpha()).isNull();
    assertThat(publishEncryptedVoters.get(0).getTrackerNumber().getEncryptedTrackerNumberInGroup()).isNull();
    assertThat(publishEncryptedVoters.get(0).getEncryptedVote()).isNotNull();
    assertThat(publishEncryptedVoters.get(0).getEncryptedVoteSignature()).isNotNull();
    assertThat(publishEncryptedVoters.get(0).getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey()).isNotNull();
    assertThat(publishEncryptedVoters.get(0).getVoterKeyPairs().getSignatureKeyPair().getPublicKey()).isNotNull();

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(4)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());
    Mockito.verify(this.cryptographyHelper).encryptVotes(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.any());

    encryptProofFile.delete();

  }
}
