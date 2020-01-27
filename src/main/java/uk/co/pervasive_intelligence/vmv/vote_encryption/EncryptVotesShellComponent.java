/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.vote_encryption;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import uk.co.pervasive_intelligence.vmv.BaseShellComponent;
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.configuration.JCommanderConfiguration;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import javax.validation.Valid;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Encrypt votes shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class EncryptVotesShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(EncryptVotesShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public EncryptVotesShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "vote_encryption.encrypt_votes.help", group = "vote_encryption.group")
  @SuppressWarnings("unchecked")
  public void encryptVotes(@ShellOption(optOut = true) @Valid final EncryptVotesOptions options) {
    try {
      LOG.info("encrypt-votes --election {} --voters {} --votes {} --commitments {} --output {} --publish {}", options.election, options.voters, options.votes,
          options.commitments, options.output, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class, JacksonViews.Public.class).get(0);

      // We might have up to three voters files: voter key pairs, plaintext voters and encryption proofs. If we have generated all of the private and public keys,
      // then there will only be the voter key pairs and plaintext voters files. However, if some keys have been created externally, and hence some votes
      // encrypted externally, then there will be the voter key pairs, plaintext voters and encryption proofs files. If all keys have been created externally and
      // hence all encryption, then there will be only the plaintext voters and encryption proofs files. We therefore attempt to read all three files in the order
      // required, catching any errors.
      List<VoterKeyPairs> votersKeyPairs = null;
      int votersIndex = 0;

      try {
        if (options.voters.size() >= 2) {
          votersKeyPairs = (List<VoterKeyPairs>) this.readCSV(options.voters.get(votersIndex), VoterKeyPairs.class);
          votersIndex++;
        }
      }
      catch (final Exception e) {
        LOG.error("encrypt-votes: could not read voters keys - assuming that votes are encrypted externally", e);
      }

      // Load in the plaintext votes. Here optional encrypted votes and their signatures can be provided instead of plaintext votes. We therefore first attempt
      // to load in the encrypted votes, which will fail, and hence we then try to load in the plaintext votes only.
      List<Voter> voters;

      try {
        voters = (List<Voter>) this.readCSV(options.voters.get(votersIndex), Voter.class, JacksonViews.ERSVoteEncryptedImport.class);
      }
      catch (final Exception e) {
        voters = (List<Voter>) this.readCSV(options.voters.get(votersIndex), Voter.class, JacksonViews.ERSVoteImport.class);
      }

      votersIndex++;

      // If no voters' keys have been supplied, build the list from the plaintext votes.
      if (votersKeyPairs == null) {
        votersKeyPairs = new ArrayList<>();

        for (final Voter voter : voters) {
          votersKeyPairs.add(voter.getVoterKeyPairs());
        }
      }

      // Attempt to read in the encryption proofs.
      List<EncryptProof> ersEncryptProofs = null;

      if (votersIndex < options.voters.size()) {
        ersEncryptProofs = (List<EncryptProof>) this.readCSV(options.voters.get(votersIndex), EncryptProof.class, JacksonViews.Public.class);
      }

      // Load in the optional vote options file and create the corresponding option numbers in the group. If no file is provided, then we extract the unique set of
      // plaintext votes instead, ignoring blank options.
      final List<VoteOption> voteOptions;

      if ((options.votes != null) && options.votes.exists()) {
        voteOptions = (List<VoteOption>) this.readCSV(options.votes, VoteOption.class, JacksonViews.ERSImport.class);
      }
      else {
        final Set<String> uniqueVotes = voters.stream().map(Voter::getPlainTextVote).collect(Collectors.toSet());
        voteOptions = uniqueVotes.stream().map(VoteOption::new).collect(Collectors.toList());
      }

      voteOptions.removeIf(option -> (option.getOption() == null) || (option.getOption().trim().length() <= 0));
      this.cryptographyHelper.mapVoteOptions(parameters, voteOptions);

      // Load in all of the private commitments files.
      final List<List<Commitment>> commitmentsLists = new ArrayList<>();

      for (final File file : options.commitments) {
        commitmentsLists.add((List<Commitment>) this.readCSV(file, Commitment.class));
      }

      // Complete the formation of the commitments and update the voter information.
      this.cryptographyHelper.completeCommitments(parameters, voters, commitmentsLists);

      // Encrypt and sign the votes for each voter and obtain the corresponding proof of knowledge of encryption.
      final ProofWrapper<List<Voter>> votersWithProof = this.cryptographyHelper.encryptVotes(parameters, keyPair, votersKeyPairs, voteOptions, voters,
          ersEncryptProofs);

      // Output the voter associated encrypted votes.
      this.writeCSV(options.output, Voter.class, votersWithProof.getObject(), JacksonViews.ERSVoteExport.class);

      // Output for publication the encrypted votes and vote options.
      this.writeCSV(options.publish.get(0), Voter.class, votersWithProof.getObject(), JacksonViews.Vote.class);
      this.writeCSV(options.publish.get(1), VoteOption.class, voteOptions, JacksonViews.Public.class);

      // Copy the proof file to the output, if it exists.
      if ((votersWithProof.getProofFile() != null) && votersWithProof.getProofFile().exists()) {
        options.publish.get(2).delete();
        Files.copy(votersWithProof.getProofFile().toPath(), options.publish.get(2).toPath());
        votersWithProof.getProofFile().delete();
      }
    }
    catch (final Exception e) {
      LOG.error("encrypt-votes:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("encrypt-votes: complete");
    }
  }

  /**
   * The command line options for {@link #encryptVotes(EncryptVotesOptions)}.
   */
  public static class EncryptVotesOptions {

    /** The commitments file. */
    @Parameter(names = "--commitments", variableArity = true, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> commitments = new ArrayList<>();

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", arity = 3, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

    /** The voters files. */
    @Parameter(names = "--voters", variableArity = true, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> voters = new ArrayList<>();

    /** The plaintext votes. */
    @Parameter(names = "--votes", converter = JCommanderConfiguration.FileConverter.class)
    File votes;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election    The public election files.
     * @param voters      The voters files.
     * @param votes       The plaintext votes.
     * @param commitments The commitments files.
     * @param output      The output file.
     * @param publish     The publish files.
     */
    public EncryptVotesOptions(final List<File> election, final List<File> voters, final File votes, final List<File> commitments, final File output,
                               final List<File> publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      if (voters != null) {
        this.voters.addAll(voters);
      }
      this.votes = votes;
      if (commitments != null) {
        this.commitments.addAll(commitments);
      }
      this.output = output;
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private EncryptVotesOptions() {
      // Do nothing.
    }
  }
}
