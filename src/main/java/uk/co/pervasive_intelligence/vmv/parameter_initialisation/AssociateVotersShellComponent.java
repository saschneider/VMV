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
import uk.co.pervasive_intelligence.vmv.cryptography.data.Voter;

import javax.validation.Valid;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

/**
 * Associate voter shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class AssociateVotersShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(AssociateVotersShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public AssociateVotersShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.associate_voter.help", group = "parameter_initialisation.group")
  @SuppressWarnings("unchecked")
  public void associateVoters(@ShellOption(optOut = true) @Valid final AssociateVotersOptions options) {
    try {
      LOG.info("associate-voters --election {} --voters {} --output {} --publish {}", options.election, options.voters, options.output, options.publish);

      // Load in the election parameters and public key.
      final Parameters parameters = (Parameters) this.readCSV(options.election.get(0), this.cryptographyHelper.getElectionParametersClass(),
          JacksonViews.Public.class).get(0);
      final KeyPair keyPair = (KeyPair) this.readCSV(options.election.get(1), KeyPair.class, JacksonViews.Public.class).get(0);

      // Load in the pre-allocated list of voters with encrypted tracker numbers and commitments.
      final List<Voter> preallocatedVoterList = (List<Voter>) this.readCSV(options.voters.get(0), Voter.class, JacksonViews.Public.class);

      // Load in the ERS voters list. This may contain just a list of ids, or a list of ids and the trapdoor and signature public keys. We read the file as if it
      // has ids and keys because the CSV reader will null out the missing keys.
      final List<Voter> ersVoterList = (List<Voter>) this.readCSV(options.voters.get(1), Voter.class, JacksonViews.ERSKeyImport.class);

      // Link the two voters lists together by setting the ID in the pre-allocated list.
      this.cryptographyHelper.associateVoters(ersVoterList, preallocatedVoterList);

      // Output the voter association ERS export.
      this.writeCSV(options.output, Voter.class, preallocatedVoterList, JacksonViews.ERSExport.class);

      // Output for publication the public voter association.
      this.writeCSV(options.publish, Voter.class, preallocatedVoterList, JacksonViews.Public.class);
    }
    catch (final Exception e) {
      LOG.error("associate-voters:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("associate-voters: complete");
    }
  }

  /**
   * The command line options for {@link #associateVoters(AssociateVotersOptions)}
   */
  public static class AssociateVotersOptions {

    /** The public election files. */
    @Parameter(names = "--election", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> election = new ArrayList<>();

    /** The output file. */
    @Parameter(names = "--output", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File output;

    /** The publish file. */
    @Parameter(names = "--publish", required = true, converter = JCommanderConfiguration.FileConverter.class)
    File publish;

    /** The voters files. */
    @Parameter(names = "--voters", arity = 2, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> voters = new ArrayList<>();

    /**
     * Constructor allow the fields to be set.
     *
     * @param election The public election files.
     * @param voters   The voters files.
     * @param output   The output file.
     * @param publish  The publish file.
     */
    public AssociateVotersOptions(final List<File> election, final List<File> voters, final File output, final File publish) {
      if (election != null) {
        this.election.addAll(election);
      }
      if (voters != null) {
        this.voters.addAll(voters);
      }
      this.output = output;
      this.publish = publish;
    }

    /**
     * Constructor for reflective instantiation.
     */
    private AssociateVotersOptions() {
      // Do nothing.
    }
  }
}
