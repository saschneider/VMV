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
 * Create commitments shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateCommitmentsShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateCommitmentsShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateCommitmentsShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_commitments.help", group = "parameter_initialisation.group")
  @SuppressWarnings("unchecked")
  public void createCommitments(@ShellOption(optOut = true) @Valid final CreateCommitmentsOptions options) {
    try {
      LOG.info("create-commitments --election {} --voters {} --tracker-numbers {} --output {} --publish {}", options.election, options.voters,
          options.trackerNumbers, options.output, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class, JacksonViews.Public.class).get(0);

      // Load in the public voter key pairs and tracker numbers.
      final List<VoterKeyPairs> votersKeyPairs = (List<VoterKeyPairs>) this.readCSV(options.voters, VoterKeyPairs.class, JacksonViews.Public.class);
      final List<TrackerNumber> trackerNumberList = (List<TrackerNumber>) this.readCSV(options.trackerNumbers, TrackerNumber.class, JacksonViews.Public.class);

      // Create the commitments.
      final ProofWrapper<List<Commitment>> commitmentsWithProof = this.cryptographyHelper.createCommitments(parameters, keyPair, votersKeyPairs,
          trackerNumberList);

      // Output the commitments.
      this.writeCSV(options.output, Commitment.class, commitmentsWithProof.getObject());

      // Output the public commitments for publication.
      this.writeCSV(options.publish.get(0), Commitment.class, commitmentsWithProof.getObject(), JacksonViews.Public.class);

      // Copy the proof file to the output, if it exists.
      if ((commitmentsWithProof.getProofFile() != null) && commitmentsWithProof.getProofFile().exists()) {
        options.publish.get(1).delete();
        Files.copy(commitmentsWithProof.getProofFile().toPath(), options.publish.get(1).toPath());
        commitmentsWithProof.getProofFile().delete();
      }
    }
    catch (final Exception e) {
      LOG.error("create-commitments:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-commitments: complete");
    }
  }

  /**
   * The command line options for {@link #createCommitments(CreateCommitmentsOptions)}.
   */
  public static class CreateCommitmentsOptions {

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

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
     * @param voters         The voter key pairs file.
     * @param trackerNumbers The tracker numbers file.
     * @param output         The output file.
     * @param publish        The publish files.
     */
    public CreateCommitmentsOptions(final List<File> election, final File voters, final File trackerNumbers, final File output, final List<File> publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      this.voters = voters;
      this.trackerNumbers = trackerNumbers;
      this.output = output;
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateCommitmentsOptions() {
      // Do nothing.
    }
  }
}
