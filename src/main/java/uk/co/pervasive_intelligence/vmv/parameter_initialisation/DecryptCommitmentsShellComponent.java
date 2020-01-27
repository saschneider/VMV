/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.parameter_initialisation;

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
 * Decrypt commitments shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class DecryptCommitmentsShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(DecryptCommitmentsShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public DecryptCommitmentsShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.decrypt_commitments.help", group = "parameter_initialisation.group")
  @SuppressWarnings("unchecked")
  public void decryptCommitments(@ShellOption(optOut = true) @Valid final DecryptCommitmentsOptions options) {
    try {
      LOG.info("decrypt-commitments --election {} --teller {} --voters {} --tracker-numbers {} --commitments {} --publish {}", options.election, options.teller,
          options.voters, options.trackerNumbers, options.commitments, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class).get(0);

      // Load in the public voter key pairs, tracker numbers.
      final List<VoterKeyPairs> votersKeyPairs = (List<VoterKeyPairs>) this.readCSV(options.voters, VoterKeyPairs.class, JacksonViews.Public.class);
      final List<TrackerNumber> trackerNumberList = (List<TrackerNumber>) this.readCSV(options.trackerNumbers, TrackerNumber.class, JacksonViews.Public.class);

      // Load in all of the commitments files.
      final List<List<Commitment>> commitmentsLists = new ArrayList<>();

      for (final File file : options.commitments) {
        commitmentsLists.add((List<Commitment>) this.readCSV(file, Commitment.class, JacksonViews.Public.class));
      }

      // Decrypt the commitments.
      final ProofWrapper<List<Voter>> votersWithProof = this.cryptographyHelper.decryptCommitments(parameters, keyPair, options.teller, votersKeyPairs,
          trackerNumberList, commitmentsLists);

      // Output the public voters for publication.
      this.writeCSV(options.publish.get(0), Voter.class, votersWithProof.getObject(), JacksonViews.Public.class);

      // Copy the proof file to the output, if it exists.
      if ((votersWithProof.getProofFile() != null) && votersWithProof.getProofFile().exists()) {
        options.publish.get(1).delete();
        Files.copy(votersWithProof.getProofFile().toPath(), options.publish.get(1).toPath());
        votersWithProof.getProofFile().delete();
      }
    }
    catch (final Exception e) {
      LOG.error("decrypt-commitments:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("decrypt-commitments: complete");
    }
  }

  /**
   * The command line options for {@link #decryptCommitments(DecryptCommitmentsOptions)}.
   */
  public static class DecryptCommitmentsOptions {

    /** The commitments file. */
    @Parameter(names = "--commitments", variableArity = true, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> commitments = new ArrayList<>();

    /** The public election file. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The publish file. */
    @Parameter(names = "--publish", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller")
    int teller;

    /** The tracker numbers file. */
    @Parameter(names = "--tracker-numbers", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File trackerNumbers;

    /** The voter key pairs file. */
    @Parameter(names = "--voters", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File voters;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election files.
     * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
     * @param voters         The voter key pairs file.
     * @param trackerNumbers The tracker numbers file.
     * @param commitments    The commitments files.
     * @param publish        The publish files.
     */
    public DecryptCommitmentsOptions(final List<File> election, final int teller, final File voters, final File trackerNumbers, final List<File> commitments,
                                     final List<File> publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      this.teller = teller;
      this.voters = voters;
      this.trackerNumbers = trackerNumbers;
      if (commitments != null) {
        this.commitments.addAll(commitments);
      }
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private DecryptCommitmentsOptions() {
      // Do nothing.
    }
  }
}
