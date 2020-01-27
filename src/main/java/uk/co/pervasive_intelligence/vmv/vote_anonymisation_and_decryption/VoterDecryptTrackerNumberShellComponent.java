/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.vote_anonymisation_and_decryption;

import com.beust.jcommander.JCommander;
import com.beust.jcommander.Parameter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.shell.standard.ShellComponent;
import org.springframework.shell.standard.ShellMethod;
import org.springframework.shell.standard.ShellOption;
import uk.co.pervasive_intelligence.vmv.BaseShellComponent;
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.configuration.JCommanderConfiguration;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;
import uk.co.pervasive_intelligence.vmv.cryptography.data.TrackerNumber;
import uk.co.pervasive_intelligence.vmv.cryptography.data.VoterKeyPairs;

import javax.validation.Valid;
import java.io.File;
import java.math.BigInteger;
import java.util.List;

/**
 * Voter decrypt tracker number shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class VoterDecryptTrackerNumberShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(VoterDecryptTrackerNumberShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /** The source for messages. */
  private final MessageSource messageSource;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   * @param messageSource      The source for messages.
   */
  public VoterDecryptTrackerNumberShellComponent(final CryptographyHelper cryptographyHelper, final MessageSource messageSource) {
    this.cryptographyHelper = cryptographyHelper;
    this.messageSource = messageSource;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "vote_anonymisation_and_decryption.voter_decrypt_tracker_number.help", group = "vote_anonymisation_and_decryption.group")
  @SuppressWarnings("unchecked")
  public void voterDecryptTrackerNumber(@ShellOption(optOut = true) @Valid final VoterDecryptTrackerNumberShellComponent.VoterDecryptTrackerNumberOptions options) {
    try {
      LOG.info("voter-decrypt-tracker-number --election {} --alpha {} --beta {} --public-key {} --voters {} --tracker-numbers {}", options.election, options.alpha,
          options.beta, options.publicKey, options.voters, options.trackerNumbers);

      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Load in the public and private voter key pairs.
      final List<VoterKeyPairs> votersKeyPairs = (List<VoterKeyPairs>) this.readCSV(options.voters, VoterKeyPairs.class);

      // Load in the tracker numbers, including their restricted elements.
      final List<TrackerNumber> trackerNumberList = (List<TrackerNumber>) this.readCSV(options.trackerNumbers, TrackerNumber.class,
          JacksonViews.RestrictedPublic.class);

      // Attempt to decrypt the tracker number.
      final TrackerNumber trackerNumber = this.cryptographyHelper.decryptTrackerNumber(parameters, options.alpha, options.beta, options.publicKey,
          votersKeyPairs, trackerNumberList);
      System.out.println(this.messageSource.getMessage("vote_anonymisation_and_decryption.voter_decrypt_tracker_number.tracker_number",
          new Object[] {trackerNumber.getTrackerNumber()}, null));
    }
    catch (final Exception e) {
      LOG.error("voter-decrypt-tracker-number:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("voter-decrypt-tracker-number: complete");
    }
  }

  /**
   * The command line options for {@link #voterDecryptTrackerNumber(VoterDecryptTrackerNumberOptions)}.
   */
  public static class VoterDecryptTrackerNumberOptions {

    /** The alpha commitment. */
    @Parameter(names = "--alpha", required = true, converter = JCommanderConfiguration.BigIntegerConverter.class)
    BigInteger alpha;

    /** The beta commitment. */
    @Parameter(names = "--beta", required = true, converter = JCommanderConfiguration.BigIntegerConverter.class)
    BigInteger beta;

    /** The public election file. */
    @Parameter(names = "--election", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File election;

    /** The voter's public encryption key. */
    @Parameter(names = "--public-key", required = true, converter = JCommanderConfiguration.BigIntegerConverter.class)
    BigInteger publicKey;

    /** The tracker numbers file. */
    @Parameter(names = "--tracker-numbers", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File trackerNumbers;

    /** The voter key pairs file. */
    @Parameter(names = "--voters", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File voters;

    /**
     * Constructor allow the fields to be set.
     *
     * @param election       The public election file.
     * @param alpha          The alpha commitment.
     * @param beta           The beta commitment.
     * @param publicKey      The voter's public encryption key.
     * @param voters         The voter file.
     * @param trackerNumbers The tracker numbers file.
     */
    public VoterDecryptTrackerNumberOptions(final File election, final BigInteger alpha, final BigInteger beta, final BigInteger publicKey, final File voters,
                                            final File trackerNumbers) {
      this.election = election;
      this.alpha = alpha;
      this.beta = beta;
      this.publicKey = publicKey;
      this.voters = voters;
      this.trackerNumbers = trackerNumbers;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private VoterDecryptTrackerNumberOptions() {
      // Do nothing.
    }
  }
}
