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

import javax.validation.Valid;
import java.io.File;
import java.nio.file.Files;

/**
 * Create teller shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateTellerShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateTellerShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateTellerShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_teller.help", group = "parameter_initialisation.group")
  public void createTeller(@ShellOption(optOut = true) @Valid final CreateTellerOptions options) {
    LOG.info("create-teller --election {} --teller {} --ip {} --teller-port {} --hint-port {} --publish {}", options.election, options.teller, options.ip,
        options.tellerPort, options.hintPort, options.publish);

    try {
      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Create the teller and obtain the path to its information file.
      final File tellerInformationFile = this.cryptographyHelper.createTeller(parameters, options.teller, options.ip, options.tellerPort, options.hintPort);

      // Copy the teller information file, if it exists.
      if ((tellerInformationFile != null) && tellerInformationFile.exists()) {
        options.publish.delete();
        Files.copy(tellerInformationFile.toPath(), options.publish.toPath());
      }
    }
    catch (final Exception e) {
      LOG.error("create-teller:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-teller: complete");
    }
  }

  /**
   * The command line options for {@link #createTeller(CreateTellerOptions)}.
   */
  public static class CreateTellerOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The teller's hint port. */
    @Parameter(names = "--hint-port")
    int hintPort = CryptographyHelper.DEFAULT_HINT_PORT;

    /** The teller's ip address (or DNS host name). If omitted, the local IP address is obtained automatically. */
    @Parameter(names = "--ip")
    String ip = CryptographyHelper.DEFAULT_TELLER_IP;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller", required = true)
    int teller;

    /** The teller's main port. */
    @Parameter(names = "--teller-port")
    int tellerPort = CryptographyHelper.DEFAULT_TELLER_PORT;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election   The public election file.
     * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
     * @param ip         The teller's ip address (or DNS host name). If omitted, the local IP address is obtained automatically.
     * @param tellerPort The teller's main port.
     * @param hintPort   The teller's hint port.
     * @param publish    The publish file.
     */
    public CreateTellerOptions(final File election, final int teller, final String ip, final int tellerPort, final int hintPort, final File publish) {
      this.election = election;
      this.teller = teller;
      this.ip = ip;
      this.tellerPort = tellerPort;
      this.hintPort = hintPort;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateTellerOptions() {
      // Do nothing.
    }
  }
}
