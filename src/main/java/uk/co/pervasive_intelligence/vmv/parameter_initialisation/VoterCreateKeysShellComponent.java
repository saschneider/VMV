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
 * Voter create keys shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class VoterCreateKeysShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(VoterCreateKeysShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public VoterCreateKeysShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.voter_create_keys.help", group = "parameter_initialisation.group")
  public void voterCreateKeys(@ShellOption(optOut = true) @Valid final VoterCreateKeysShellComponent.VoterCreateKeysOptions options) {
    try {
      LOG.info("voter-create-keys --election {} --output {} --publish {}", options.election, options.output, options.publish);

      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Create the voter's trapdoor and signature key pairs.
      final List<VoterKeyPairs> keyPairs = this.cryptographyHelper.createVotersKeyPairs(1, parameters);

      // Output the private and public voter parameters and key pairs.
      this.writeCSV(options.output, VoterKeyPairs.class, keyPairs);

      // Output for publication the public voter parameters and public keys.
      this.writeCSV(options.publish, VoterKeyPairs.class, keyPairs, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("voter-create-keys:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("voter-create-keys: complete");
    }
  }

  /**
   * The command line options for {@link #voterCreateKeys(VoterCreateKeysOptions)}.
   */
  public static class VoterCreateKeysOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election The public election file.
     * @param output   The output file.
     * @param publish  The publish file.
     */
    public VoterCreateKeysOptions(final File election, final File output, final File publish) {
      this.election = election;
      this.output = output;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private VoterCreateKeysOptions() {
      // Do nothing.
    }
  }
}
