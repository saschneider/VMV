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
import uk.co.pervasive_intelligence.vmv.cryptography.AlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;

import javax.validation.Valid;
import java.io.File;

/**
 * Create election parameters shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateElectionParametersShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateElectionParametersShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateElectionParametersShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_election_parameters.help", group = "parameter_initialisation.group")
  public void createElectionParameters(@ShellOption(optOut = true) @Valid final CreateElectionParametersOptions options) {
    LOG.info("create-election-parameters --publish {} --name {} --no-tellers {} --number-of-tellers {} --threshold-tellers {} --dsa-l {} --dsa-n {} " +
            "--prime-certainty {}",
        options.publish, options.name, options.noTellers, options.numberOfTellers, options.thresholdTellers, options.dsaL, options.dsaN, options.primeCertainty);

    try {
      // Create the election parameters.
      final Parameters parameters = this.cryptographyHelper.createElectionParameters(options.dsaL, options.dsaN, options.primeCertainty);
      parameters.setName(options.name);

      if (options.noTellers) {
        parameters.setNumberOfTellers(0);
        parameters.setThresholdTellers(0);
      }
      else {
        parameters.setNumberOfTellers(options.numberOfTellers);
        parameters.setThresholdTellers(options.thresholdTellers);
      }

      // Output for publication the public parameters.
      this.writeCSV(options.publish, parameters.getClass(), parameters, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("create-election-parameters:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-election-parameters: complete");
    }
  }

  /**
   * The command line options for {@link #createElectionParameters(CreateElectionParametersOptions)}.
   */
  public static class CreateElectionParametersOptions {

    /** Optional DSA L parameter. */
    @Parameter(names = "--dsa-l")
    int dsaL = AlgorithmHelper.DEFAULT_LENGTH_L;

    /** Optional DSA N parameter. */
    @Parameter(names = "--dsa-n")
    int dsaN = AlgorithmHelper.DEFAULT_LENGTH_N;

    /** The name of the election. */
    @Parameter(names = "--name", required = true)
    String name;

    /** Disable the use of tellers? */
    @Parameter(names = "--no-tellers")
    boolean noTellers = false;

    /** The number of tellers. */
    @Parameter(names = "--number-of-tellers")
    int numberOfTellers = CryptographyHelper.DEFAULT_NUMBER_OF_TELLERS;

    /** Optional prime certainty to use in parameter generation. */
    @Parameter(names = "--prime-certainty")
    int primeCertainty = AlgorithmHelper.DEFAULT_PRIME_CERTAINTY;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /** The threshold number of tellers. */
    @Parameter(names = "--threshold-tellers")
    int thresholdTellers = CryptographyHelper.DEFAULT_THRESHOLD_TELLERS;

    /**
     * Constructor allow the fields to be set.
     *
     * @param publish          The publish file
     * @param name             The name of the election.
     * @param noTellers        Disable the use of tellers?
     * @param numberOfTellers  The number of tellers.
     * @param thresholdTellers The threshold number of tellers.
     * @param dsaL             Optional DSA L parameter.
     * @param dsaN             Optional DSA N parameter.
     * @param primeCertainty   Optional prime certainty to use in parameter generation.
     */
    public CreateElectionParametersOptions(final File publish, final String name, final boolean noTellers, final int numberOfTellers, final int thresholdTellers,
                                           final int dsaL, final int dsaN, final int primeCertainty) {
      this.publish = publish;
      this.name = name;
      this.noTellers = noTellers;
      this.numberOfTellers = numberOfTellers;
      this.thresholdTellers = thresholdTellers;
      this.dsaL = dsaL;
      this.dsaN = dsaN;
      this.primeCertainty = primeCertainty;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateElectionParametersOptions() {
      // Do nothing.
    }
  }
}
