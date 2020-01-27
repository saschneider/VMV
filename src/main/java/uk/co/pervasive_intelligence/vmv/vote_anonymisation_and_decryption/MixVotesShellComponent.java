/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.vote_anonymisation_and_decryption;

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

/**
 * Mix votes shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class MixVotesShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(MixVotesShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public MixVotesShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "vote_anonymisation_and_decryption.mix_votes.help", group = "vote_anonymisation_and_decryption.group")
  @SuppressWarnings("unchecked")
  public void mixVotes(@ShellOption(optOut = true) @Valid final MixVotesOptions options) {
    try {
      LOG.info("shuffle-votes --election {} --teller {} --tracker-numbers {} --votes {} --voters {} --publish {}", options.election, options.teller,
          options.trackerNumbers, options.votes, options.voters, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class).get(0);

      // Load in the vote options.
      final List<VoteOption> voteOptions = (List<VoteOption>) this.readCSV(options.votes, VoteOption.class, JacksonViews.Public.class);

      // Load in the tracker numbers, including their restricted elements.
      final List<TrackerNumber> trackerNumberList = (List<TrackerNumber>) this.readCSV(options.trackerNumbers, TrackerNumber.class,
          JacksonViews.RestrictedPublic.class);

      // Load in the encrypted votes.
      final List<Voter> encryptedVoters = (List<Voter>) this.readCSV(options.voters, Voter.class, JacksonViews.Vote.class);

      // Mix the votes.
      final ProofWrapper<List<Voter>> votersWithProof = this.cryptographyHelper.mixVotes(parameters, keyPair, options.teller, trackerNumberList, voteOptions,
          encryptedVoters);

      // Output for publication the mixed votes and proofs.
      this.writeCSV(options.publish.get(0), Voter.class, votersWithProof.getObject(), JacksonViews.Mixed.class);

      // Copy the proof file to the output, if it exists.
      if ((votersWithProof.getProofFile() != null) && votersWithProof.getProofFile().exists()) {
        options.publish.get(1).delete();
        Files.copy(votersWithProof.getProofFile().toPath(), options.publish.get(1).toPath());
        votersWithProof.getProofFile().delete();
      }
    }
    catch (final Exception e) {
      LOG.error("mix-votes:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("mix-votes: complete");
    }
  }

  /**
   * The command line options for {@link #mixVotes(MixVotesOptions)}.
   */
  public static class MixVotesOptions {

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The publish files. */
    @Parameter(names = "--publish", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller")
    int teller;

    /** The tracker numbers file. */
    @Parameter(names = "--tracker-numbers", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File trackerNumbers;

    /** The encrypted votes per voter. */
    @Parameter(names = "--voters", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File voters;

    /** The vote options file. */
    @Parameter(names = "--votes", converter = JCommanderConfiguration.FileConverter.class)
    File votes;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election files.
     * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
     * @param trackerNumbers The tracker numbers file.
     * @param votes          The vote options file.
     * @param voters         The encrypted votes per voter.
     * @param publish        The publish files.
     */
    public MixVotesOptions(final List<File> election, final int teller, final File trackerNumbers, final File votes, final File voters, final List<File> publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      this.teller = teller;
      this.votes = votes;
      this.trackerNumbers = trackerNumbers;
      this.voters = voters;
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private MixVotesOptions() {
      // Do nothing.
    }
  }
}
