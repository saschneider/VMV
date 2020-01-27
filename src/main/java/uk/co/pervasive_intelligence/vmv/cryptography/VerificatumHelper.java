/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;

import java.io.*;
import java.math.BigInteger;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * This class provides an interface to the Verificatum suite of programmes in order to perform required distributed operations.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class VerificatumHelper {

  /** URL HTTP prefix. */
  private static final String HTTP = "http://";

  /** JSON file extension */
  private static final String JSON_EXTENSION = ".json";

  /** Platform line separator. */
  private static final String LINE_SEPARATOR = System.getProperty("line.separator");

  /** The local IP address on which the teller and hint port listen. */
  private static final String LOCAL_IP_ADDRESS = "0.0.0.0";

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(DSAAlgorithmHelper.class);

  /** Mix-net operation: decrypt. */
  private static final String OPERATION_DECRYPT = "-decrypt";

  /** The JSON input file for a mix-net operation. */
  private static final String OPERATION_IN_JSON_FILENAME = "operation_in" + JSON_EXTENSION;

  /** Mix-net operation: mix. */
  private static final String OPERATION_MIX = "-mix";

  /** The JSON output file from a mix-net operation. */
  private static final String OPERATION_OUT_JSON_FILENAME = "operation_out" + JSON_EXTENSION;

  /** Mix-net operation auxiliary session identifier: decrypt. */
  private static final String OPERATION_SESSION_DECRYPT = "decrypt";

  /** Mix-net operation auxiliary session identifier: mix. */
  private static final String OPERATION_SESSION_MIX = "mix";

  /** Mix-net operation auxiliary session identifier: shuffle. */
  private static final String OPERATION_SESSION_SHUFFLE = "shuffle";

  /** Mix-net operation: shuffle. */
  private static final String OPERATION_SHUFFLE = "-shuffle";

  /** Mix-net operation output type: ciphertexts. */
  private static final String OUTPUT_CIPHERTEXTS = "-ciphs";

  /** Mix-net operation output type: plaintexts. */
  private static final String OUTPUT_PLAINTEXTS = "-plain";

  /** URL port separator. */
  private static final String PORT_SEPARATOR = ":";

  /** The directory in which the shuffle/mix/decrypt proof is held. */
  private static final File PROOF_DIRECTORY = new File("dir", "nizkp");

  /** The JSON public key file. */
  private static final String PUBLIC_KEY_JSON_FILENAME = "publicKey" + JSON_EXTENSION;

  /** Raw file extension */
  private static final String RAW_EXTENSION = ".raw";

  /** The raw public key file. */
  private static final String PUBLIC_KEY_RAW_FILENAME = "publicKey" + RAW_EXTENSION;

  /** The raw input file for a mix-net operation. */
  private static final String OPERATION_IN_RAW_FILENAME = "operation_in" + RAW_EXTENSION;

  /** The raw output file from a mix-net operation. */
  private static final String OPERATION_OUT_RAW_FILENAME = "operation_out" + RAW_EXTENSION;

  /** The top-level Verificatum session identifier. */
  private static final String SESSION = "ElectionSession";

  /** The teller name. */
  private static final String TELLER_NAME = "Teller";

  /** XML file extension */
  private static final String XML_EXTENSION = ".xml";

  /** The created local teller information file. */
  private static final String LOCAL_TELLER_INFO_FILENAME = "localProtInfo" + XML_EXTENSION;

  /** The merged public teller information file. */
  private static final String TELLER_PUBLIC_INFO_FILENAME = "protInfo" + XML_EXTENSION;

  /** The private teller information file. */
  private static final String TELLER_PRIVATE_INFO_FILENAME = "privInfo" + XML_EXTENSION;

  /**
   * Constructs the teller directory.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The directory for the teller.
   */
  public static File getTellerDirectory(final Parameters parameters, final int teller) {
    return new File(getTellerName(parameters, teller));
  }

  /**
   * Constructs the name of the teller information file.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The name for the teller.
   */
  private static File getTellerInfoFile(final Parameters parameters, final int teller) {
    return new File(getTellerName(parameters, teller) + XML_EXTENSION);
  }

  /**
   * Constructs the name for a teller.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The name for the teller.
   */
  private static String getTellerName(final Parameters parameters, final int teller) {
    final int padding = Integer.toString(parameters.getNumberOfTellers()).length();
    return String.format("%s%0" + padding + "d", TELLER_NAME, teller);
  }

  /**
   * Creates the election key pair using an existing Verificatum session. Each teller will have their own share of the secret key and hence the output is only the
   * public key.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The created key pair with only the public key present.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  public KeyPair createElectionKeyPair(final Parameters parameters, final int teller) throws CryptographyException {
    // Create the key pair.
    final File tellerDirectory = getTellerDirectory(parameters, teller);

    final String[] keygenCommand = new String[] {"vmn", "-keygen", PUBLIC_KEY_RAW_FILENAME};
    this.runCommand(keygenCommand, tellerDirectory);

    // Decode the created public key.
    final String[] convertCommand = new String[] {"vmnc", "-pkey", "-outi", "json", TELLER_PUBLIC_INFO_FILENAME, PUBLIC_KEY_RAW_FILENAME, PUBLIC_KEY_JSON_FILENAME};
    this.runCommand(convertCommand, tellerDirectory);

    try {
      final File publicKeyJSONFile = new File(tellerDirectory, PUBLIC_KEY_JSON_FILENAME);
      final ObjectMapper mapper = new ObjectMapper();
      final JsonNode node = mapper.readTree(publicKeyJSONFile);
      final String publicKey = node.get("y").asText();

      return new KeyPair(null, new BigInteger(publicKey));
    }
    catch (final Exception e) {
      throw new CryptographyException("could not decode public key JSON", e);
    }
  }

  /**
   * Creates a Verificatum teller, returning its information file which should be shared with all other tellers.
   *
   * @param parameters  The election parameters.
   * @param teller      The number of the teller. Each teller has a unique number, starting at 1.
   * @param hostAddress The teller's address (or DNS host name).
   * @param tellerPort  The teller's main port.
   * @param hintPort    The teller's hint port.
   * @return The path to the teller's information file which needs to be copied to all tellers.
   * @throws CryptographyException if the teller could not be setup.
   */
  public File createTeller(final Parameters parameters, final int teller, final String hostAddress, final int tellerPort, final int hintPort) throws CryptographyException {
    try {
      // Encode the group parameters.
      final String groupParameters = this.encodeGroupParameters(parameters);

      // We advertise the public address and ports for the teller and the hint server, but listen on a local IP address.
      final URL publicTellerURL = new URL(HTTP + hostAddress + PORT_SEPARATOR + tellerPort);
      final String publicHintHostPort = hostAddress + PORT_SEPARATOR + hintPort;

      final URL localTellerURL = new URL(HTTP + LOCAL_IP_ADDRESS + PORT_SEPARATOR + tellerPort);
      final String localHintHostPort = LOCAL_IP_ADDRESS + PORT_SEPARATOR + hintPort;

      // Create the teller with the encoded parameters.
      final String tellerName = getTellerName(parameters, teller);
      final File tellerDirectory = getTellerDirectory(parameters, teller);
      tellerDirectory.mkdirs();

      final String[] initialiseCommand = new String[] {
          "vmni", "-prot", "-sid", SESSION, "-name", parameters.getName(), "-nopart", Integer.toString(parameters.getNumberOfTellers()), "-thres",
          Integer.toString(parameters.getThresholdTellers()), "-pgroup", groupParameters};
      this.runCommand(initialiseCommand, tellerDirectory);

      final String[] initialiseTellerCommand = new String[] {"vmni", "-party", "-name", tellerName,
          "-http", publicTellerURL.toString(), "-hint", publicHintHostPort,
          "-httpl", localTellerURL.toString(), "-hintl", localHintHostPort};
      this.runCommand(initialiseTellerCommand, tellerDirectory);

      // Copy the teller information to a file with a sensible name.
      final File localInfo = new File(tellerDirectory, LOCAL_TELLER_INFO_FILENAME);
      final File tellerInfoFile = new File(tellerDirectory, getTellerInfoFile(parameters, teller).toString());
      tellerInfoFile.delete();
      Files.copy(localInfo.toPath(), tellerInfoFile.toPath());

      return tellerInfoFile;
    }
    catch (final CryptographyException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create teller start", e);
    }
  }

  /**
   * Decrypts a list of ciphertexts.
   *
   * @param parameters  The election parameters.
   * @param teller      The number of the teller. Each teller has a unique number, starting at 1.
   * @param width       The number of ciphertexts to be operated on as a block.
   * @param cipherTexts The list of ciphertexts to be decrypted.
   * @return The decrypted plaintexts with the corresponding proof file.
   * @throws CryptographyException if the operation could not be performed.
   */
  public ProofWrapper<List<BigInteger>> decrypt(final Parameters parameters, final int teller, final int width, final List<CipherText> cipherTexts) throws CryptographyException {
    // Perform the operation and obtain the JSON output file with the corresponding proof file.
    final ProofWrapper<File> outputWithProof = this.operation(parameters, teller, OPERATION_DECRYPT, OPERATION_SESSION_DECRYPT, width, cipherTexts);

    // Load in the plaintexts from the JSON output file.
    final List<BigInteger> plainTexts = this.readPlainTexts(outputWithProof.getObject());

    return new ProofWrapper<>(plainTexts, outputWithProof.getProofFile());
  }

  /**
   * Encodes the group parameters so that they can be used by Verificatum.
   *
   * @param parameters The parameters to encode.
   * @return The encoded group parameters.
   * @throws CryptographyException if the parameters could not be encoded.
   */
  private String encodeGroupParameters(final Parameters parameters) throws CryptographyException {
    if (!(parameters instanceof DHParametersWrapper)) {
      throw new CryptographyException("Could not encode parameters: wrong class " + parameters.getClass().getName());
    }

    final DHParametersWrapper wrapper = ((DHParametersWrapper) parameters);
    final String[] command = new String[] {"vog", "-gen", "ModPGroup", "-explic", "-roenc", wrapper.getP().toString(16), wrapper.getG().toString(16),
        wrapper.getQ().toString(16)};

    return this.runCommand(command);
  }

  /**
   * Gets the array of local teller information files in order for all tellers. The files are assumed to be held within the specified teller directory.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The array of local teller information files.
   * @throws CryptographyException if incorrect teller information is provided.
   */
  public File[] getTellerInformationFiles(final Parameters parameters, final int teller) throws CryptographyException {
    final File[] tellerInformationFiles = new File[parameters.getNumberOfTellers()];

    final File tellerDirectory = getTellerDirectory(parameters, teller);

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerInfoFile = getTellerInfoFile(parameters, i);
      tellerInformationFiles[i - 1] = new File(tellerDirectory, tellerInfoFile.toString());
    }

    return tellerInformationFiles;
  }

  /**
   * Merges the Verificatum teller information files ready to perform key generation, shuffling, mixing or decryption.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @throws CryptographyException if the teller could not be setup.
   */
  public void mergeTeller(final Parameters parameters, final int teller) throws CryptographyException {
    // Make sure all of the teller files have been copied.
    final File tellerDirectory = getTellerDirectory(parameters, teller);

    // Combine all of the teller files.
    final List<String> mergeCommand = new ArrayList<>(Arrays.asList("vmni", "-merge"));

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerInfoFile = getTellerInfoFile(parameters, i);
      final File path = new File(tellerDirectory, tellerInfoFile.toString());

      if (!path.exists()) {
        throw new CryptographyException("Could not finish creation of teller as missing " + tellerInfoFile.toString() + " teller information file");
      }

      mergeCommand.add(tellerInfoFile.toString());
    }

    this.runCommand(mergeCommand.toArray(new String[0]), tellerDirectory);
  }

  /**
   * Mixes a list of ciphertexts.
   *
   * @param parameters  The election parameters.
   * @param teller      The number of the teller. Each teller has a unique number, starting at 1.
   * @param width       The number of ciphertexts to be operated on as a block.
   * @param cipherTexts The list of ciphertexts to be mixed.
   * @return The mixed and decrypted plaintexts with the corresponding proof file.
   * @throws CryptographyException if the operation could not be performed.
   */
  public ProofWrapper<List<BigInteger>> mix(final Parameters parameters, final int teller, final int width, final List<CipherText> cipherTexts) throws CryptographyException {
    // Perform the operation and obtain the JSON output file with the corresponding proof file.
    final ProofWrapper<File> outputWithProof = this.operation(parameters, teller, OPERATION_MIX, OPERATION_SESSION_MIX, width, cipherTexts);

    // Load in the plaintexts from the JSON output file.
    final List<BigInteger> plainTexts = this.readPlainTexts(outputWithProof.getObject());

    return new ProofWrapper<>(plainTexts, outputWithProof.getProofFile());
  }

  /**
   * Shuffles, mixes or decrypts a list of ciphertexts.
   *
   * @param parameters         The election parameters.
   * @param teller             The number of the teller. Each teller has a unique number, starting at 1.
   * @param operation          The operation to be performed: "shuffle", "mix" or "decrypt".
   * @param width              The number of ciphertexts to be operated on as a block.
   * @param auxiliarySessionId The auxiliary session identifier for the shuffle.
   * @param cipherTexts        The list of ciphertexts to be operated on.
   * @return The output file which contains either the shuffled (and re-encrypted) ciphertexts or the plaintexts.
   * @throws CryptographyException if the operation could not be performed.
   */
  private ProofWrapper<File> operation(final Parameters parameters, final int teller, final String operation, final String auxiliarySessionId, final int width,
                                       final List<CipherText> cipherTexts) throws CryptographyException {
    // Write the ciphertexts to file.
    final File tellerDirectory = getTellerDirectory(parameters, teller);
    final File inputJSONFile = new File(tellerDirectory, OPERATION_IN_JSON_FILENAME);
    final File outputJSONFile = new File(tellerDirectory, OPERATION_OUT_JSON_FILENAME);
    this.writeCipherTexts(inputJSONFile, width, cipherTexts);

    // Convert the input ciphertexts into raw format.
    final String[] inCommand = new String[] {"vmnc", "-ciphs", "-ini", "json", "-width", Integer.toString(width), TELLER_PUBLIC_INFO_FILENAME,
        OPERATION_IN_JSON_FILENAME, OPERATION_IN_RAW_FILENAME};
    this.runCommand(inCommand, tellerDirectory);

    // Perform the operation on the ciphertexts.
    final String[] operationCommand = new String[] {"vmn", operation, "-auxsid", auxiliarySessionId, "-width", Integer.toString(width),
        TELLER_PRIVATE_INFO_FILENAME, TELLER_PUBLIC_INFO_FILENAME, OPERATION_IN_RAW_FILENAME, OPERATION_OUT_RAW_FILENAME};
    this.runCommand(operationCommand, tellerDirectory);

    // Convert the output into JSON format.
    final String output = OPERATION_SHUFFLE.equals(operation) ? OUTPUT_CIPHERTEXTS : OUTPUT_PLAINTEXTS;
    final String[] outCommand = new String[] {"vmnc", output, "-outi", "json", "-width", Integer.toString(width), TELLER_PUBLIC_INFO_FILENAME,
        OPERATION_OUT_RAW_FILENAME, OPERATION_OUT_JSON_FILENAME};
    this.runCommand(outCommand, tellerDirectory);

    // ZIP the protocol information and proof files. These are the same on all tellers. We temporarily copy the protocol information into the proof directory so
    // that it is included in the ZIP file.
    final File protocolInformationFile = new File(tellerDirectory, TELLER_PUBLIC_INFO_FILENAME);
    final Path proofPath = Paths.get(tellerDirectory.toString(), PROOF_DIRECTORY.toString(), auxiliarySessionId);
    final File protocolInformationProofFile = new File(proofPath.toFile(), TELLER_PUBLIC_INFO_FILENAME);
    File zipFile;

    try {
      Files.copy(protocolInformationFile.toPath(), protocolInformationProofFile.toPath());
      zipFile = Files.createTempFile(null, null).toFile();
      this.zipDirectory(proofPath, zipFile.toPath());
    }
    catch (final CryptographyException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create proof file", e);
    }
    finally {
      protocolInformationProofFile.delete();
    }

    return new ProofWrapper<>(outputJSONFile, zipFile);
  }

  /**
   * Reads a list of ciphertexts from (almost) a JSON file.
   *
   * @param file The input file.
   * @return The read ciphertexts.
   * @throws CryptographyException if the ciphertexts could not be read from file.
   */
  private List<CipherText> readCipherTexts(final File file) throws CryptographyException {
    BufferedReader reader = null;

    try {
      reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));

      // Verificatum does not output properly formed JSON, instead it writes JSON objects on a line-by-line basis.
      final List<CipherText> cipherTexts = new ArrayList<>();
      final ObjectMapper mapper = new ObjectMapper();
      String line;

      while ((line = reader.readLine()) != null) {
        cipherTexts.add(mapper.readValue(line, CipherText.class));
      }

      return cipherTexts;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not read ciphertexts JSON", e);
    }
    finally {
      try {
        if (reader != null) {
          reader.close();
        }
      }
      catch (final Exception e) {
        // Log only as we may already be throwing an exception.
        LOG.error("Could not close file", e);
      }
    }
  }

  /**
   * Reads a list of plaintexts from (not really) a JSON file.
   *
   * @param file The input file.
   * @return The read plaintexts.
   * @throws CryptographyException if the plaintexts could not be read from file.
   */
  private List<BigInteger> readPlainTexts(final File file) throws CryptographyException {
    BufferedReader reader = null;

    try {
      reader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));

      // Verificatum does not output properly formed JSON, instead it writes big integers as decimal strings on a line-by-line basis with multiple values per width.
      final List<BigInteger> plainTexts = new ArrayList<>();
      String line;

      while ((line = reader.readLine()) != null) {
        final String[] values = line.split(",");

        for (final String value : values) {
          plainTexts.add(new BigInteger(value.replaceAll("[\\p{Punct}\\s]*", "")));
        }
      }

      return plainTexts;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not read plaintexts JSON", e);
    }
    finally {
      try {
        if (reader != null) {
          reader.close();
        }
      }
      catch (final Exception e) {
        // Log only as we may already be throwing an exception.
        LOG.error("Could not close file", e);
      }
    }
  }

  /**
   * Runs a command in the specified directory and obtains its output. If the command fails, an {@link CryptographyException} is thrown.
   *
   * @param command   The command to execute.
   * @param directory The directory in which the command shoudl be run. Leave null to use the current working directory.
   * @return The output of the command.
   * @throws CryptographyException if the command failed.
   */
  private String runCommand(final String[] command, final File directory) throws CryptographyException {
    try {
      LOG.debug("Command: {} {}", directory, command);
      final Process process = Runtime.getRuntime().exec(command, null, directory);
      final int status = process.waitFor();

      final String output = new BufferedReader(new InputStreamReader(process.getInputStream())).lines().collect(Collectors.joining(LINE_SEPARATOR));
      if (output.length() > 0) {
        LOG.debug("Command output: {}", output);
      }

      final String error = new BufferedReader(new InputStreamReader(process.getErrorStream())).lines().collect(Collectors.joining(LINE_SEPARATOR));
      if (error.length() > 0) {
        LOG.debug("Command error: {}", error);
      }

      if (status != 0) {
        throw new CryptographyException("Command failed with exit code " + status + ": " + output + "; " + error);
      }

      return output;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not run command: \"" + String.join(" ", command) + "\"", e);
    }
  }

  /**
   * Runs a command in the local directory and obtains its output. If the command fails, an {@link CryptographyException} is thrown.
   *
   * @param command The command to execute.
   * @return The output of the command.
   * @throws CryptographyException if the command failed.
   */
  private String runCommand(final String[] command) throws CryptographyException {
    return this.runCommand(command, null);
  }

  /**
   * Shuffles a list of ciphertexts.
   *
   * @param parameters  The election parameters.
   * @param teller      The number of the teller. Each teller has a unique number, starting at 1.
   * @param width       The number of ciphertexts to be operated on as a block.
   * @param cipherTexts The list of ciphertexts to be shuffled.
   * @return The shuffled (and re-encrypted) ciphertexts with the corresponding proof file.
   * @throws CryptographyException if the operation could not be performed.
   */
  public ProofWrapper<List<CipherText>> shuffle(final Parameters parameters, final int teller, final int width, final List<CipherText> cipherTexts) throws CryptographyException {
    // Perform the operation and obtain the JSON output file with the corresponding proof file.
    final ProofWrapper<File> outputWithProof = this.operation(parameters, teller, OPERATION_SHUFFLE, OPERATION_SESSION_SHUFFLE, width, cipherTexts);

    // Load in the shuffled ciphertexts from the JSON output file.
    final List<CipherText> shuffled = this.readCipherTexts(outputWithProof.getObject());

    return new ProofWrapper<>(shuffled, outputWithProof.getProofFile());
  }

  /**
   * Writes a list of ciphertexts to (almost) a JSON file ready for import into Verificatum. One pair of ciphertext values is written per width per line.
   *
   * @param file        The output file.
   * @param width       The number of ciphertexts to be operated on as a block.
   * @param cipherTexts The ciphertexts to write.
   * @throws CryptographyException if the ciphertexts could not be written to file.
   */
  private void writeCipherTexts(final File file, final int width, final List<CipherText> cipherTexts) throws CryptographyException {
    PrintWriter writer = null;

    try {
      writer = new PrintWriter(new BufferedWriter(new FileWriter(file, false)));

      // Verificatum does not expect properly formed JSON as an input, instead it expects JSON objects on a line-by-line basis.
      final ObjectMapper mapper = new ObjectMapper();
      mapper.configure(JsonGenerator.Feature.WRITE_NUMBERS_AS_STRINGS, true); // Make sure BigIntegers are written as strings since Verificatum expects this.

      for (int i = 0; i < cipherTexts.size(); i += width) {
        if (width > 1) {
          writer.print("[");
        }

        for (int j = 0; j < width; j++) {
          writer.print(mapper.writeValueAsString(cipherTexts.get(i + j)));

          if (j < (width - 1)) {
            writer.print(",");
          }
        }

        if (width > 1) {
          writer.print("]");
        }

        writer.println();
      }
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not write ciphertexts JSON", e);
    }
    finally {
      try {
        if (writer != null) {
          writer.close();
        }
      }
      catch (final Exception e) {
        // Log only as we may already be throwing an exception.
        LOG.error("Could not close file", e);
      }
    }
  }

  /**
   * ZIPs the specified directory into the specified ZIP file. Based on https://stackoverflow.com/questions/15968883/how-to-zip-a-folder-itself-using-java.
   *
   * @param directory The directory to ZIP.
   * @param zipFile   The output ZIP file.
   * @throws CryptographyException if the directory could not be ZIPped.
   */
  public void zipDirectory(final Path directory, final Path zipFile) throws CryptographyException {
    try {
      try (final ZipOutputStream zipOutputStream = new ZipOutputStream(Files.newOutputStream(zipFile))) {
        Files.walk(directory)
            .filter(path -> !Files.isDirectory(path))
            .forEach(path -> {
              final ZipEntry zipEntry = new ZipEntry(directory.relativize(path).toString());

              try {
                zipOutputStream.putNextEntry(zipEntry);
                Files.copy(path, zipOutputStream);
                zipOutputStream.closeEntry();
              }
              catch (final Exception e) {
                throw new RuntimeException(e); // Re-throw as an unchecked exception because of the lambda.
              }
            });
      }
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create ZIP file", e);
    }
  }
}
