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
import uk.co.pervasive_intelligence.vmv.cryptography.data.ProofWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.TrackerNumber;

import javax.validation.Valid;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Shuffle tracker numbers shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class ShuffleTrackerNumbersShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ShuffleTrackerNumbersShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public ShuffleTrackerNumbersShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.shuffle_tracker_numbers.help", group = "parameter_initialisation.group")
  @SuppressWarnings("unchecked")
  public void shuffleTrackerNumbers(@ShellOption(optOut = true) @Valid final ShuffleTrackerNumbersOptions options) {
    try {
      LOG.info("shuffle-tracker-numbers --election {} --teller {} --tracker-numbers {} --publish {}", options.election, options.teller, options.trackerNumbers,
          options.publish);

      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Load in the tracker numbers, including their restricted elements.
      final List<TrackerNumber> trackerNumberList = (List<TrackerNumber>) this.readCSV(options.trackerNumbers, TrackerNumber.class,
          JacksonViews.RestrictedPublic.class);

      // Shuffle the tracker numbers.
      final ProofWrapper<List<TrackerNumber>> shuffledTrackerNumbersWithProof = this.cryptographyHelper.shuffleTrackerNumbers(parameters, options.teller,
          trackerNumberList);

      // Output for publication the shuffled tracker numbers.
      this.writeCSV(options.publish.get(0), TrackerNumber.class, shuffledTrackerNumbersWithProof.getObject(), JacksonViews.Public.class);

      // Copy the proof file to the output, if it exists.
      if ((shuffledTrackerNumbersWithProof.getProofFile() != null) && shuffledTrackerNumbersWithProof.getProofFile().exists()) {
        options.publish.get(1).delete();
        Files.copy(shuffledTrackerNumbersWithProof.getProofFile().toPath(), options.publish.get(1).toPath());
        shuffledTrackerNumbersWithProof.getProofFile().delete();
      }
    }
    catch (final Exception e) {
      LOG.error("shuffle-tracker-numbers:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("shuffle-tracker-numbers: complete");
    }
  }

  /**
   * The command line options for {@link #shuffleTrackerNumbers(ShuffleTrackerNumbersOptions)}.
   */
  public static class ShuffleTrackerNumbersOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The publish file. */
    @Parameter(names = "--publish", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> publish = new ArrayList<>();

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller")
    int teller;

    /** The tracker numbers file. */
    @Parameter(names = "--tracker-numbers", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File trackerNumbers;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election file.
     * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
     * @param trackerNumbers The tracker numbers.
     * @param publish        The publish files.
     */
    public ShuffleTrackerNumbersOptions(final File election, final int teller, final File trackerNumbers, final List<File> publish) {
      this.election = election;
      this.teller = teller;
      this.trackerNumbers = trackerNumbers;
      if (publish != null) {
        this.publish.addAll(publish);
      }
    }

    /**
     * Constructor for reflective instantiation.
     */
    private ShuffleTrackerNumbersOptions() {
      // Do nothing.
    }
  }
}
