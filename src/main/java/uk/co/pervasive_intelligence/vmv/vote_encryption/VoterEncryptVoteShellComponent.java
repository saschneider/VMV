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
import java.util.Collections;
import java.util.List;

/**
 * Voter encrypt vote shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class VoterEncryptVoteShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(VoterEncryptVoteShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public VoterEncryptVoteShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "vote_encryption.voter_encrypt_vote.help", group = "vote_encryption.group")
  @SuppressWarnings("unchecked")
  public void voterEncryptVote(@ShellOption(optOut = true) @Valid final VoterEncryptVoteShellComponent.VoterEncryptVoteOptions options) {
    try {
      LOG.info("voter-encrypt-vote {} --election {} --voter {} --votes {} --publish {}", options.vote, options.election, options.voter, options.votes,
          options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class, JacksonViews.Public.class).get(0);

      // Load in the voter key pairs.
      final List<VoterKeyPairs> votersKeyPairs = (List<VoterKeyPairs>) this.readCSV(options.voter, VoterKeyPairs.class);

      // Load in the vote options file.
      final List<VoteOption> voteOptions = (List<VoteOption>) this.readCSV(options.votes, VoteOption.class, JacksonViews.ERSImport.class);

      // Build the voter information. We assume that the first set of voter key pairs relate to the voter.
      final Voter voter = new Voter();
      voter.setPlainTextVote(options.vote.get(0));
      voter.setVoterKeyPairs(votersKeyPairs.get(0));

      // Encrypt and sign the vote and obtain the corresponding proof of knowledge of encryption.
      final ProofWrapper<List<Voter>> votersWithProof = this.cryptographyHelper.encryptVotes(parameters, keyPair, votersKeyPairs, voteOptions,
          Collections.singletonList(voter), null);

      // Output for publication the encrypted vote.
      this.writeCSV(options.publish.get(0), Voter.class, votersWithProof.getObject(), JacksonViews.VoterVote.class);

      // Copy the proof file to the output, if it exists.
      if ((votersWithProof.getProofFile() != null) && votersWithProof.getProofFile().exists()) {
        options.publish.get(1).delete();
        Files.copy(votersWithProof.getProofFile().toPath(), options.publish.get(1).toPath());
        votersWithProof.getProofFile().delete();
      }

    }
    catch (final Exception e) {
      LOG.error("voter-encrypt-vote:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("voter-encrypt-vote: complete");
    }
  }

  /**
   * The command line options for {@link #voterEncryptVote(VoterEncryptVoteOptions)}.
   */
  public static class VoterEncryptVoteOptions {

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The publish files. */
    @Parameter(names = "--publish", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

    /** The plaintext vote - the JCommander parameter must be a list, apparently. */
    @Parameter(required = true)
    List<String> vote = new ArrayList<>();

    /** The voter key pairs file. */
    @Parameter(names = "--voter", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File voter;

    /** The vote options. */
    @Parameter(names = "--votes", converter = JCommanderConfiguration.FileConverter.class)
    File votes;

    /**
     * Constructor allow the fields to be set.
     *
     * @param vote     The plaintext vote.
     * @param election The public election files.
     * @param voter    The voter key pairs file.
     * @param votes    The vote options.
     * @param publish  The publish files.
     */
    public VoterEncryptVoteOptions(final List<String> vote, final List<File> election, final File voter, final File votes, final List<File> publish) {
      if (vote != null) {
        this.vote.addAll(vote);
      }
      if (election != null) {
        this.election.addAll(election);
      }
      this.voter = voter;
      this.votes = votes;
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private VoterEncryptVoteOptions() {
      // Do nothing.
    }
  }
}
