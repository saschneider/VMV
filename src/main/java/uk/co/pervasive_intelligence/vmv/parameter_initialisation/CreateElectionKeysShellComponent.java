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
import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;

import javax.validation.Valid;
import java.io.File;

/**
 * Create election keys shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateElectionKeysShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateElectionKeysShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateElectionKeysShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_election_keys.help", group = "parameter_initialisation.group")
  public void createElectionKeys(@ShellOption(optOut = true) @Valid final CreateElectionKeysOptions options) {
    LOG.info("create-election-keys --election {} --teller {} --output {} --publish {}", options.election, options.teller, options.output, options.publish);

    try {
      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Create the election key pair.
      final KeyPair keyPair = this.cryptographyHelper.createElectionKeyPair(parameters, options.teller);

      // Output the private (if available) and public key.
      this.writeCSV(options.output, keyPair.getClass(), keyPair);

      // Output for publication the public key.
      this.writeCSV(options.publish, keyPair.getClass(), keyPair, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("create-election-keys:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-election-keys: complete");
    }
  }

  /**
   * The command line options for {@link #createElectionKeys(CreateElectionKeysOptions)}.
   */
  public static class CreateElectionKeysOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller")
    int teller;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election The public election file.
     * @param teller   The number of the teller. Each teller has a unique number, starting at 1.
     * @param output   The output file.
     * @param publish  The publish file.
     */
    public CreateElectionKeysOptions(final File election, final int teller, final File output, final File publish) {
      this.election = election;
      this.teller = teller;
      this.output = output;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateElectionKeysOptions() {
      // Do nothing.
    }
  }
}
