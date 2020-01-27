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
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;
import uk.co.pervasive_intelligence.vmv.cryptography.data.VoterKeyPairs;

import javax.validation.Valid;
import java.io.File;
import java.util.List;

/**
 * Create voter keys shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateVotersKeysShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateVotersKeysShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateVotersKeysShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_voters_keys.help", group = "parameter_initialisation.group")
  public void createVotersKeys(@ShellOption(optOut = true) @Valid final CreateVotersKeysOptions options) {
    try {
      LOG.info("create-voters-keys --election {} --number-of-voters {} --output {} --publish {}", options.election, options.numberOfVoters, options.output,
          options.publish);

      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Create each voter's trapdoor and signature key pairs.
      final List<VoterKeyPairs> keyPairs = this.cryptographyHelper.createVotersKeyPairs(options.numberOfVoters, parameters);

      // Output the private and public voter parameters and key pairs.
      this.writeCSV(options.output, VoterKeyPairs.class, keyPairs);

      // Output for publication the public voter parameters and public keys.
      this.writeCSV(options.publish, VoterKeyPairs.class, keyPairs, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("create-voters-keys:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-voters-keys: complete");
    }
  }

  /**
   * The command line options for {@link #createVotersKeys(CreateVotersKeysOptions)}.
   */
  public static class CreateVotersKeysOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The number of voters. */
    @Parameter(names = "--number-of-voters", required = true)
    int numberOfVoters;

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election file.
     * @param numberOfVoters The number of voters.
     * @param output         The output file.
     * @param publish        The publish file.
     */
    public CreateVotersKeysOptions(final File election, final int numberOfVoters, final File output, final File publish) {
      this.election = election;
      this.numberOfVoters = numberOfVoters;
      this.output = output;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateVotersKeysOptions() {
      // Do nothing.
    }
  }
}
