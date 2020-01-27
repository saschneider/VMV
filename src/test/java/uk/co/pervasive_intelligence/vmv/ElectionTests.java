/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import org.apache.commons.io.FileDeleteStrategy;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.context.MessageSource;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.SeleneCryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.VerificatumHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.ChaumPedersenAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.SchnorrAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.parameter_initialisation.*;
import uk.co.pervasive_intelligence.vmv.vote_anonymisation_and_decryption.MixVotesShellComponent;
import uk.co.pervasive_intelligence.vmv.vote_anonymisation_and_decryption.VoterDecryptTrackerNumberShellComponent;
import uk.co.pervasive_intelligence.vmv.vote_encryption.EncryptVotesShellComponent;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.IntStream;

import static org.assertj.core.api.AssertionsForInterfaceTypes.assertThat;

/**
 * Election end-to-end tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class ElectionTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final String commitmentsProofs = "commitments-proofs-%d.csv";

  private final String decryptProofs = "decrypt-proofs-%d.zip";

  private final File encryptProofs = new File("encrypt-proofs.csv");

  private final File ersAssociatedVoters = new File("ers-associated-voters.csv");

  private final File ersEncryptProofs = new File("ers-encrypt-proofs.csv");

  private final File ersEncryptedVoters = new File("ers-encrypted-voters.csv");

  private final File ersPlainTextVoters = new File("ers-plaintext-voters.csv");

  private final File ersVoteOptions = new File("ers-vote-options.csv");

  private final File ersVoters = new File("ers-voters.csv");

  private final String mixProofs = "mix-proofs-%d.zip";

  private final String outputCommitmentsFile = "commitments-%d.csv";

  private final File outputElectionKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishAssociatedVoters = new File("public-associated-voters.csv");

  private final String publishCommitmentsFile = "public-commitments-%d.csv";

  private final File publishElectionKeys = new File("public-election-keys.csv");

  private final File publishElectionParams = new File("public-election-params.csv");

  private final File publishEncryptedVoters = new File("public-encrypted-voters.csv");

  private final File publishMixedVoters = new File("public-mixed-voters.csv");

  private final String publishTellerInformationFile = "teller-information-%d.xml";

  private final File publishTrackerNumbers = new File("public-tracker-numbers.csv");

  private final File publishVoteOptions = new File("public-vote-options.csv");

  private final File publishVoters = new File("public-voters.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  private final String shuffleProofs = "shuffle-proofs-%d.zip";

  private final File shuffledTrackerNumbers = new File("shuffled-tracker-numbers.csv");

  @Mock
  private MessageSource messageSource;

  private List<VoteOption> createERSVoterOptions(final int numberOfVoters) {
    final List<VoteOption> ersVoterOptions = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      ersVoterOptions.add(new VoteOption(Integer.toString(i)));
    }

    return ersVoterOptions;
  }

  private List<Voter> createERSVoters(final int numberOfVoters) {
    final List<Voter> ersVoters = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      ersVoters.add(new Voter(i));
    }

    return ersVoters;
  }

  private File[][] createFiles(final int numberOfTellers, final String... fileNameTemplates) {
    final File[][] files = new File[fileNameTemplates.length][numberOfTellers];

    for (int i = 0; i < fileNameTemplates.length; i++) {
      for (int j = 0; j < numberOfTellers; j++) {
        files[i][j] = new File(String.format(fileNameTemplates[i], j + 1));
      }
    }

    return files;
  }

  private ProofWrapper<List<Voter>> encryptPlainTextVotes(final CryptographyHelper cryptographyHelper, final Parameters parameters, final KeyPair keyPair,
                                                          final List<VoterKeyPairs> votersKeyPairs, final List<VoteOption> voteOptions, final List<Voter> voters) throws Exception {
    // Encrypt all of the plaintext votes.
    final ProofWrapper<List<Voter>> encryptedVotersWithProof = cryptographyHelper.encryptVotes(parameters, keyPair, votersKeyPairs, voteOptions, voters, null);

    // Clear out all of the plaintext votes.
    for (final Voter voter : encryptedVotersWithProof.getObject()) {
      voter.setPlainTextVote(null);
    }

    return encryptedVotersWithProof;
  }

  @SuppressWarnings("unchecked")
  public void runElection(final int numberOfVoters, final int numberOfTellers, final boolean internalKeys) throws Exception {
    final File[][] commitmentFiles = this.createFiles(numberOfTellers, this.outputCommitmentsFile, this.publishCommitmentsFile);
    this.tidyFiles(commitmentFiles);

    final File[][] tellerInformationFiles = this.createFiles(numberOfTellers, this.publishTellerInformationFile);
    this.tidyFiles(tellerInformationFiles);

    final File[][] shuffleProofsFiles = this.createFiles(numberOfTellers, this.shuffleProofs);
    this.tidyFiles(shuffleProofsFiles);

    final File[][] commitmentsProofsFiles = this.createFiles(numberOfTellers, this.commitmentsProofs);
    this.tidyFiles(commitmentsProofsFiles);

    final File[][] decryptProofsFiles = this.createFiles(numberOfTellers, this.decryptProofs);
    this.tidyFiles(decryptProofsFiles);

    final File[][] mixProofsFiles = this.createFiles(numberOfTellers, this.mixProofs);
    this.tidyFiles(mixProofsFiles);

    // Cryptography helpers.
    final DSAAlgorithmHelper dsaAlgorithmHelper = new DSAAlgorithmHelper();
    final ElGamalAlgorithmHelper elGamalAlgorithmHelper = new ElGamalAlgorithmHelper();
    final VerificatumHelper verificatumHelper = new VerificatumHelper();
    final SchnorrAlgorithmHelper schnorrAlgorithmHelper = new SchnorrAlgorithmHelper();
    final ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper = new ChaumPedersenAlgorithmHelper();
    final SeleneCryptographyHelper cryptographyHelper = new SeleneCryptographyHelper(this.messageSource, dsaAlgorithmHelper, elGamalAlgorithmHelper,
        verificatumHelper, schnorrAlgorithmHelper, chaumPedersenAlgorithmHelper);

    // Start the executor.
    final ExecutorService executor = Executors.newFixedThreadPool(numberOfTellers);

    // Create election parameters.
    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(cryptographyHelper);
    final CreateElectionParametersShellComponent.CreateElectionParametersOptions createElectionParametersOptions =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishElectionParams, "Test Election", numberOfTellers == 1, 4, 3, 3072,
            256, 128);
    createElectionParametersShellComponent.createElectionParameters(createElectionParametersOptions);

    final TestShellComponent testShellComponent = new TestShellComponent();
    final Parameters parameters = (Parameters) testShellComponent.readCSV(this.publishElectionParams, cryptographyHelper.getElectionParametersClass(),
        JacksonViews.Public.class).get(0);

    if (numberOfTellers > 1) {
      // Optionally create teller.
      final List<Callable<Void>> createTellersTasks = new ArrayList<>();
      IntStream.range(1, numberOfTellers + 1).forEach(i -> {
        createTellersTasks.add(() -> {
          final CreateTellerShellComponent createTellerShellComponent = new CreateTellerShellComponent(cryptographyHelper);
          final CreateTellerShellComponent.CreateTellerOptions createTellerOptions =
              new CreateTellerShellComponent.CreateTellerOptions(this.publishElectionParams, i, "127.0.0.1", 8080 + i, 4040 + i, tellerInformationFiles[0][i - 1]);
          createTellerShellComponent.createTeller(createTellerOptions);

          return null;
        });
      });
      final List<Future<Void>> createTellersFutures = executor.invokeAll(createTellersTasks);
      for (int i = 0; i < numberOfTellers; i++) {
        createTellersFutures.get(i).get();
      }

      // Optionally merge tellers.
      final List<Callable<Void>> mergeTellersTasks = new ArrayList<>();
      IntStream.range(1, numberOfTellers + 1).forEach(i -> {
        mergeTellersTasks.add(() -> {
          final MergeTellerShellComponent mergeTellerShellComponent = new MergeTellerShellComponent(cryptographyHelper);
          final MergeTellerShellComponent.MergeTellerOptions mergeTellerOptions = new MergeTellerShellComponent.MergeTellerOptions(this.publishElectionParams, i,
              Arrays.asList(tellerInformationFiles[0]));
          mergeTellerShellComponent.mergeTeller(mergeTellerOptions);

          return null;
        });
      });
      final List<Future<Void>> mergeTellersFutures = executor.invokeAll(mergeTellersTasks);
      for (int i = 0; i < numberOfTellers; i++) {
        mergeTellersFutures.get(i).get();
      }
    }

    // Create election keys.
    final List<Callable<Void>> createElectionKeysTasks = new ArrayList<>();
    IntStream.range(1, numberOfTellers + 1).forEach(i -> {
      createElectionKeysTasks.add(() -> {
        final CreateElectionKeysShellComponent createElectionKeysShellComponent = new CreateElectionKeysShellComponent(cryptographyHelper);
        final CreateElectionKeysShellComponent.CreateElectionKeysOptions createElectionKeysOptions =
            new CreateElectionKeysShellComponent.CreateElectionKeysOptions(this.publishElectionParams, i, this.outputElectionKeys, this.publishElectionKeys);
        createElectionKeysShellComponent.createElectionKeys(createElectionKeysOptions);

        return null;
      });
    });
    final List<Future<Void>> createElectionKeysFutures = executor.invokeAll(createElectionKeysTasks);
    for (int i = 0; i < numberOfTellers; i++) {
      createElectionKeysFutures.get(i).get();
    }

    final KeyPair electionKeyPair = (KeyPair) testShellComponent.readCSV(this.publishElectionKeys, KeyPair.class, JacksonViews.Public.class).get(0);

    // Create voter keys: we do this for both internal (demonstrator created keys) and external (externally created keys) keys. When external, we simply do not
    // supply the private keys to the demonstrator.
    final CreateVotersKeysShellComponent createVotersKeysShellComponent = new CreateVotersKeysShellComponent(cryptographyHelper);
    final CreateVotersKeysShellComponent.CreateVotersKeysOptions createVotersKeysOptions =
        new CreateVotersKeysShellComponent.CreateVotersKeysOptions(this.publishElectionParams, numberOfVoters, this.outputVotersKeys, this.publishVotersKeys);
    createVotersKeysShellComponent.createVotersKeys(createVotersKeysOptions);

    final List<VoterKeyPairs> votersKeyPairs = (List<VoterKeyPairs>) testShellComponent.readCSV(this.outputVotersKeys, VoterKeyPairs.class);

    // Create tracker numbers.
    final CreateTrackerNumbersShellComponent createTrackerNumbersShellComponent = new CreateTrackerNumbersShellComponent(cryptographyHelper);
    final CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions createTrackerNumbersOptions =
        new CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions(Arrays.asList(this.publishElectionParams, this.publishElectionKeys), numberOfVoters,
            this.publishTrackerNumbers);
    createTrackerNumbersShellComponent.createTrackerNumbers(createTrackerNumbersOptions);

    // Shuffle tracker numbers.
    final List<Callable<Void>> shuffleTrackerNumberTasks = new ArrayList<>();
    IntStream.range(1, numberOfTellers + 1).forEach(i -> {
      shuffleTrackerNumberTasks.add(() -> {
        final ShuffleTrackerNumbersShellComponent shuffleTrackerNumbersShellComponent = new ShuffleTrackerNumbersShellComponent(cryptographyHelper);
        final ShuffleTrackerNumbersShellComponent.ShuffleTrackerNumbersOptions shuffleTrackerNumbersOptions =
            new ShuffleTrackerNumbersShellComponent.ShuffleTrackerNumbersOptions(this.publishElectionParams, i, this.publishTrackerNumbers,
                Arrays.asList(this.shuffledTrackerNumbers, shuffleProofsFiles[0][i - 1]));
        shuffleTrackerNumbersShellComponent.shuffleTrackerNumbers(shuffleTrackerNumbersOptions);

        return null;
      });
    });
    final List<Future<Void>> shuffleTrackerNumberFutures = executor.invokeAll(shuffleTrackerNumberTasks);
    for (int i = 0; i < numberOfTellers; i++) {
      shuffleTrackerNumberFutures.get(i).get();
    }

    // Create commitments.
    final List<Callable<Void>> createCommitmentsTasks = new ArrayList<>();
    IntStream.range(1, numberOfTellers + 1).forEach(i -> {
      createCommitmentsTasks.add(() -> {
        final CreateCommitmentsShellComponent createCommitmentsShellComponent = new CreateCommitmentsShellComponent(cryptographyHelper);
        final CreateCommitmentsShellComponent.CreateCommitmentsOptions createCommitmentsOptions =
            new CreateCommitmentsShellComponent.CreateCommitmentsOptions(Arrays.asList(this.publishElectionParams, this.publishElectionKeys),
                this.publishVotersKeys,
                this.shuffledTrackerNumbers, commitmentFiles[0][i - 1], Arrays.asList(commitmentFiles[1][i - 1], commitmentsProofsFiles[0][i - 1]));
        createCommitmentsShellComponent.createCommitments(createCommitmentsOptions);

        return null;
      });
    });
    final List<Future<Void>> createCommitmentsFutures = executor.invokeAll(createCommitmentsTasks);
    for (int i = 0; i < numberOfTellers; i++) {
      createCommitmentsFutures.get(i).get();
    }

    // Decrypt commitments.
    final List<Callable<Void>> decryptCommitmentsTasks = new ArrayList<>();
    IntStream.range(1, numberOfTellers + 1).forEach(i -> {
      decryptCommitmentsTasks.add(() -> {
        final DecryptCommitmentsShellComponent decryptCommitmentsShellComponent = new DecryptCommitmentsShellComponent(cryptographyHelper);
        final DecryptCommitmentsShellComponent.DecryptCommitmentsOptions decryptCommitmentsOptions =
            new DecryptCommitmentsShellComponent.DecryptCommitmentsOptions(Arrays.asList(this.publishElectionParams, this.outputElectionKeys), i,
                this.publishVotersKeys, this.shuffledTrackerNumbers, Arrays.asList(commitmentFiles[1]), Arrays.asList(this.publishVoters,
                decryptProofsFiles[0][i - 1]));
        decryptCommitmentsShellComponent.decryptCommitments(decryptCommitmentsOptions);

        return null;
      });
    });
    final List<Future<Void>> decryptCommitmentsFutures = executor.invokeAll(decryptCommitmentsTasks);
    for (int i = 0; i < numberOfTellers; i++) {
      decryptCommitmentsFutures.get(i).get();
    }

    // Associate voters.
    final AssociateVotersShellComponent associateVotersShellComponent = new AssociateVotersShellComponent(cryptographyHelper);
    final AssociateVotersShellComponent.AssociateVotersOptions associateVotersOptions =
        new AssociateVotersShellComponent.AssociateVotersOptions(Arrays.asList(this.publishElectionParams, this.publishElectionKeys),
            Arrays.asList(this.publishVoters, this.ersVoters), this.ersAssociatedVoters, this.publishAssociatedVoters);
    associateVotersShellComponent.writeCSV(this.ersVoters, Voter.class, this.createERSVoters(numberOfVoters), JacksonViews.ERSImport.class);
    associateVotersShellComponent.associateVoters(associateVotersOptions);

    // Encrypt votes. If external keys are being used, then we supply only the pre-encrypted votes with public keys and encryption proofs without the plaintext
    // votes, plus the previously mapped vote options.
    final EncryptVotesShellComponent encryptVotesShellComponent = new EncryptVotesShellComponent(cryptographyHelper);
    final EncryptVotesShellComponent.EncryptVotesOptions encryptVotesOptions;
    final List<Voter> voters = (List<Voter>) associateVotersShellComponent.readCSV(this.ersAssociatedVoters, Voter.class, JacksonViews.ERSExport.class);

    if (internalKeys) {
      // Set up the demonstrator to map the vote options and encrypt the votes using the keys.
      associateVotersShellComponent.writeCSV(this.ersPlainTextVoters, Voter.class, this.updatePlainTextVotes(voters), JacksonViews.ERSVoteImport.class);
      associateVotersShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, this.createERSVoterOptions(numberOfVoters), JacksonViews.ERSImport.class);

      encryptVotesOptions = new EncryptVotesShellComponent.EncryptVotesOptions(Arrays.asList(this.publishElectionParams, this.publishElectionKeys),
          Arrays.asList(this.outputVotersKeys, this.ersPlainTextVoters), this.ersVoteOptions,
          Arrays.asList(commitmentFiles[0]), this.ersEncryptedVoters, Arrays.asList(this.publishEncryptedVoters, this.publishVoteOptions,
          this.encryptProofs));
    }
    else {
      // Pre-encrypt the plaintext votes using the keys with pre-mapped vote options.
      final List<VoteOption> voteOptions = this.createERSVoterOptions(numberOfVoters);
      cryptographyHelper.mapVoteOptions(parameters, voteOptions);
      associateVotersShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, voteOptions, JacksonViews.ERSImport.class);

      final ProofWrapper<List<Voter>> encryptedVotersWithProof = this.encryptPlainTextVotes(cryptographyHelper, parameters, electionKeyPair, votersKeyPairs,
          voteOptions, this.updatePlainTextVotes(voters));
      associateVotersShellComponent.writeCSV(this.ersPlainTextVoters, Voter.class, encryptedVotersWithProof.getObject(), JacksonViews.ERSVoteEncryptedImport.class);

      if ((encryptedVotersWithProof.getProofFile() != null) && encryptedVotersWithProof.getProofFile().exists()) {
        this.ersEncryptProofs.delete();
        Files.copy(encryptedVotersWithProof.getProofFile().toPath(), this.ersEncryptProofs.toPath());
        encryptedVotersWithProof.getProofFile().delete();
      }

      encryptVotesOptions = new EncryptVotesShellComponent.EncryptVotesOptions(Arrays.asList(this.publishElectionParams, this.publishElectionKeys),
          Arrays.asList(this.ersPlainTextVoters, this.ersEncryptProofs), this.ersVoteOptions,
          Arrays.asList(commitmentFiles[0]), this.ersEncryptedVoters, Arrays.asList(this.publishEncryptedVoters, this.publishVoteOptions,
          this.encryptProofs));
    }

    encryptVotesShellComponent.encryptVotes(encryptVotesOptions);

    // Mix votes.
    final List<Callable<Void>> mixVotesTasks = new ArrayList<>();
    IntStream.range(1, numberOfTellers + 1).forEach(i -> {
      mixVotesTasks.add(() -> {
        final MixVotesShellComponent mixVotesShellComponent = new MixVotesShellComponent(cryptographyHelper);
        final MixVotesShellComponent.MixVotesOptions mixVotesOptions = new MixVotesShellComponent.MixVotesOptions(Arrays.asList(this.publishElectionParams,
            this.outputElectionKeys), i, this.publishTrackerNumbers, this.publishVoteOptions, this.publishEncryptedVoters,
            Arrays.asList(this.publishMixedVoters, mixProofsFiles[0][i - 1]));
        mixVotesShellComponent.mixVotes(mixVotesOptions);

        return null;
      });
    });
    final List<Future<Void>> mixVotesFutures = executor.invokeAll(mixVotesTasks);
    for (int i = 0; i < numberOfTellers; i++) {
      mixVotesFutures.get(i).get();
    }

    // Shutdown the executor.
    try {
      if (!executor.awaitTermination(60, TimeUnit.SECONDS)) {
        executor.shutdownNow();
      }
    }
    catch (final InterruptedException e) {
      executor.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Check the plaintext votes are as expected by decrypting the alpha and beta using the voter's private trapdoor key to get the tracker number.
    final List<TrackerNumber> trackerNumbers = (List<TrackerNumber>) testShellComponent.readCSV(this.publishTrackerNumbers, TrackerNumber.class,
        JacksonViews.RestrictedPublic.class);
    final List<Voter> votersWithPlainText = (List<Voter>) testShellComponent.readCSV(this.publishMixedVoters, Voter.class, JacksonViews.Mixed.class);
    final List<Voter> votersWithBeta = (List<Voter>) testShellComponent.readCSV(this.ersAssociatedVoters, Voter.class, JacksonViews.ERSExport.class);
    final List<Voter> votersWithAlpha = (List<Voter>) testShellComponent.readCSV(this.ersEncryptedVoters, Voter.class, JacksonViews.ERSVoteExport.class);

    final VoterDecryptTrackerNumberShellComponent voterDecryptTrackerNumberShellComponent = new VoterDecryptTrackerNumberShellComponent(cryptographyHelper,
        this.messageSource);

    for (int i = 0; i < numberOfVoters; i++) {
      final long id = votersWithAlpha.get(i).getId();
      final BigInteger alpha = votersWithAlpha.get(i).getAlpha();

      final Voter foundId = votersWithBeta.stream().filter(voter -> voter.getId().equals(id)).findAny().orElse(null);
      assertThat(foundId).isNotNull();

      final BigInteger beta = foundId.getBeta();
      final BigInteger publicKey = foundId.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey();

      // The following should not throw an exception but produces no output, so it's only here to make sure this works.
      final VoterDecryptTrackerNumberShellComponent.VoterDecryptTrackerNumberOptions voterDecryptTrackerNumberOptions =
          new VoterDecryptTrackerNumberShellComponent.VoterDecryptTrackerNumberOptions(this.publishElectionParams, alpha, beta, publicKey, this.outputVotersKeys,
              this.publishTrackerNumbers);
      voterDecryptTrackerNumberShellComponent.voterDecryptTrackerNumber(voterDecryptTrackerNumberOptions);

      final TrackerNumber trackerNumber = cryptographyHelper.decryptTrackerNumber(parameters, alpha, beta, publicKey, votersKeyPairs, trackerNumbers);
      AssertionsForClassTypes.assertThat(trackerNumber).isNotNull();

      // We are expecting a vote if a vote was cast.
      final Voter foundVoter =
          votersWithPlainText.stream().filter(voter -> voter.getTrackerNumber().getTrackerNumber().equals(trackerNumber.getTrackerNumber())).findAny().orElse(null);
      final byte[] encryptedVote = voters.get(i).getEncryptedVote();
      final String plainTextVote = voters.get(i).getPlainTextVote();

      if (((plainTextVote != null) && (plainTextVote.trim().length() > 0)) || ((encryptedVote != null) && (encryptedVote.length > 0))) {
        assertThat(foundVoter).isNotNull();

        if ((plainTextVote != null) && (plainTextVote.trim().length() > 0)) {
          assertThat(foundVoter.getPlainTextVote()).isEqualTo(Long.toString(id));
        }
      }
      else {
        assertThat(foundVoter).isNull();
      }
    }

    this.tidyFiles(commitmentFiles);
    this.tidyFiles(tellerInformationFiles);
    this.tidyFiles(commitmentsProofsFiles);
    this.tidyFiles(shuffleProofsFiles);
    this.tidyFiles(decryptProofsFiles);
    this.tidyFiles(mixProofsFiles);
  }

  @Before
  @After
  public void setUp() throws Exception {
    this.ersAssociatedVoters.delete();
    this.ersEncryptProofs.delete();
    this.ersEncryptedVoters.delete();
    this.ersPlainTextVoters.delete();
    this.ersVoteOptions.delete();
    this.ersVoters.delete();
    this.outputElectionKeys.delete();
    this.outputVotersKeys.delete();
    this.publishAssociatedVoters.delete();
    this.publishElectionKeys.delete();
    this.publishElectionParams.delete();
    this.publishEncryptedVoters.delete();
    this.publishMixedVoters.delete();
    this.publishTrackerNumbers.delete();
    this.publishVoteOptions.delete();
    this.publishVoters.delete();
    this.publishVotersKeys.delete();
    this.shuffledTrackerNumbers.delete();
    this.encryptProofs.delete();

    final DHParametersWrapper parameters = new DHParametersWrapper(null);
    parameters.setNumberOfTellers(4);

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerDirectory = VerificatumHelper.getTellerDirectory(parameters, i);
      FileDeleteStrategy.FORCE.delete(tellerDirectory);
    }
  }

  @Test
  public void testElectionNoTellersExternalKeys() throws Exception {
    this.runElection(100, 1, false);
  }

  @Test
  public void testElectionNoTellersInternalKeys() throws Exception {
    this.runElection(100, 1, true);
  }

  @Test
  public void testElectionTellersExternalKeys() throws Exception {
    this.runElection(100, 4, false);
  }

  @Test
  public void testElectionTellersInternalKeys() throws Exception {
    this.runElection(100, 4, true);
  }

  private void tidyFiles(final File[][] files) {
    for (final File[] moreFiles : files) {
      for (final File file : moreFiles) {
        file.delete();
      }
    }
  }

  private List<Voter> updatePlainTextVotes(final List<Voter> voters) {
    for (int i = 0; i < voters.size(); i++) {
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
      voters.get(i).setPlainTextVote(plainTextVote);
    }

    return voters;
  }

  private static class TestShellComponent extends BaseShellComponent {

  }
}
