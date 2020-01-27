/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
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
import uk.co.pervasive_intelligence.vmv.cryptography.data.VoteOption;

import javax.validation.Valid;
import java.io.File;
import java.util.List;

/**
 * Map vote options shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class MapVoteOptionsShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(MapVoteOptionsShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public MapVoteOptionsShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.map_vote_options.help", group = "parameter_initialisation.group")
  @SuppressWarnings("unchecked")
  public void mapVoteOptions(@ShellOption(optOut = true) @Valid final MapVoteOptionsShellComponent.MapVoteOptionsOptions options) {
    LOG.info("map-vote-options --election {} --votes {} --publish {}", options.election, options.voteOptions, options.publish);

    try {
      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Load in the vote options file.
      final List<VoteOption> voteOptions = (List<VoteOption>) this.readCSV(options.voteOptions, VoteOption.class, JacksonViews.ERSImport.class);

      // Remove any blank vote options and create the corresponding option numbers in the group (preserving any that have been pre-assigned).
      voteOptions.removeIf(option -> (option.getOption() == null) || (option.getOption().trim().length() <= 0));
      this.cryptographyHelper.mapVoteOptions(parameters, voteOptions);

      // Output for publication the mapped vote options.
      this.writeCSV(options.publish, VoteOption.class, voteOptions, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("map-vote-options:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("map-vote-options: complete");
    }
  }

  /**
   * The command line options for {@link #mapVoteOptions(MapVoteOptionsOptions)}.
   */
  public static class MapVoteOptionsOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true)
    File election;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /** The plaintext votes. */
    @Parameter(names = "--vote-options", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File voteOptions;

    /**
     * Constructor for reflective instantiation.
     */
    private MapVoteOptionsOptions() {
      // Do nothing.
    }

    /**
     * Constructor allow the fields to be set.
     *
     * @param election    The public election files.
     * @param voteOptions The vote options file.
     * @param publish     The publish file.
     */
    public MapVoteOptionsOptions(final File election, final File voteOptions, final File publish) {
      this.election = election;
      this.voteOptions = voteOptions;
      this.publish = publish;
    }
  }
}
