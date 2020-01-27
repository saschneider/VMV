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
import uk.co.pervasive_intelligence.vmv.cryptography.data.TrackerNumber;

import javax.validation.Valid;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Create tracker numbers shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class CreateTrackerNumbersShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(CreateTrackerNumbersShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public CreateTrackerNumbersShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.create_tracker_numbers.help", group = "parameter_initialisation.group")
  public void createTrackerNumbers(@ShellOption(optOut = true) @Valid final CreateTrackerNumbersOptions options) {
    try {
      LOG.info("create-tracker-numbers --election {} --number-of-voters {} --publish {}", options.election, options.numberOfVoters, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class, JacksonViews.Public.class).get(0);

      // Create the tracker numbers.
      final List<TrackerNumber> trackerNumbers = new ArrayList<>(this.cryptographyHelper.createTrackerNumbers(parameters, keyPair, options.numberOfVoters));

      // Output for publication the tracker numbers, including the restricted elements.
      this.writeCSV(options.publish, TrackerNumber.class, trackerNumbers, JacksonViews.RestrictedPublic.class);
    }
    catch (final Exception e) {
      LOG.error("create-tracker-numbers:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("create-tracker-numbers: complete");
    }
  }

  /**
   * The command line options for {@link #createTrackerNumbers(CreateTrackerNumbersOptions)}.
   */
  public static class CreateTrackerNumbersOptions {

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The number of voters. */
    @Parameter(names = "--number-of-voters", required = true)
    int numberOfVoters;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election files.
     * @param numberOfVoters The number of voters.
     * @param publish        The publish file.
     */
    public CreateTrackerNumbersOptions(final List<File> election, final int numberOfVoters, final File publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      this.numberOfVoters = numberOfVoters;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private CreateTrackerNumbersOptions() {
      // Do nothing.
    }
  }
}
