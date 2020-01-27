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
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Parameters;

import javax.validation.Valid;
import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * Merge teller shell command.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@ShellComponent
public class MergeTellerShellComponent extends BaseShellComponent {

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(MergeTellerShellComponent.class);

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param cryptographyHelper The cryptography helper.
   */
  public MergeTellerShellComponent(final CryptographyHelper cryptographyHelper) {
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Shell command.
   *
   * @param options The {@link JCommander} options.
   */
  @ShellMethod(value = "parameter_initialisation.merge_teller.help", group = "parameter_initialisation.group")
  public void mergeTeller(@ShellOption(optOut = true) @Valid final MergeTellerShellComponent.MergeTellerOptions options) {
    LOG.info("merge-teller --election {} --teller {} --teller-information {}", options.election, options.teller, options.tellerInformation);

    try {
      // Load in the election parameters.
      final Parameters parameters =
          (Parameters) this.readCSV(options.election, this.cryptographyHelper.getElectionParametersClass(), JacksonViews.Public.class).get(0);

      // Copy all of the teller information files to their corresponding local files in the local teller directory. This assumes the files are correct and in the
      // right order for each teller.
      final File[] localFiles = this.cryptographyHelper.getTellerInformationFiles(parameters, options.teller);

      if (options.tellerInformation.size() != localFiles.length) {
        throw new CryptographyException("Number of teller information files and expected number do not match: " + options.tellerInformation.size() + " vs. " + localFiles.length);
      }

      for (int i = 0; i < localFiles.length; i++) {
        localFiles[i].delete();
        Files.copy(options.tellerInformation.get(i).toPath(), localFiles[i].toPath());
      }

      // Merge the tellers.
      this.cryptographyHelper.mergeTeller(parameters, options.teller, options.tellerInformation.toArray(new File[0]));
    }
    catch (final Exception e) {
      LOG.error("merge-teller:", e);
      throw new RuntimeException(e); // Re-throw the exception so that it is displayed prettily.
    }
    finally {
      LOG.info("merge-teller: complete");
    }
  }

  /**
   * The command line options for {@link #mergeTeller(MergeTellerOptions)}.
   */
  public static class MergeTellerOptions {

    /** The public election file. */
    @Parameter(names = "--election", required = true)
    File election;

    /** The number of the teller. Each teller has a unique number, starting at 1. */
    @Parameter(names = "--teller", required = true)
    int teller;

    /** The teller information files. */
    @Parameter(names = "--teller-information", variableArity = true, required = true, converter = JCommanderConfiguration.FileConverter.class)
    List<File> tellerInformation = new ArrayList<>();

    /**
     * Constructor for reflective instantiation.
     */
    private MergeTellerOptions() {
      // Do nothing.
    }

    /**
     * Constructor allow the fields to be set.
     *
     * @param election          The public election file.
     * @param teller            The number of the teller. Each teller has a unique number, starting at 1.
     * @param tellerInformation The teller information files.
     */
    public MergeTellerOptions(final File election, final int teller, final List<File> tellerInformation) {
      this.election = election;
      this.teller = teller;
      this.tellerInformation.addAll(tellerInformation);
    }
  }
}
