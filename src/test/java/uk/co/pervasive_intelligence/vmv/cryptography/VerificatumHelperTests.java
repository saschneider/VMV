/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.apache.commons.io.FileDeleteStrategy;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.data.CipherText;
import uk.co.pervasive_intelligence.vmv.cryptography.data.DHParametersWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;
import uk.co.pervasive_intelligence.vmv.cryptography.data.ProofWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.*;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verificatum helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class VerificatumHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Before
  @After
  public void setup() throws Exception {
    final DHParametersWrapper parameters = new DHParametersWrapper(null);
    parameters.setNumberOfTellers(4);

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerDirectory = VerificatumHelper.getTellerDirectory(parameters, i);
      FileDeleteStrategy.FORCE.delete(tellerDirectory);
    }
  }

  @Test
  public void testVerificatum() throws Exception {
    // One big test as each stage requires the preceding one.
    final DSAAlgorithmHelper dsaAlgorithmHelper = new DSAAlgorithmHelper();
    final DHParametersWrapper parameters = (DHParametersWrapper) dsaAlgorithmHelper.createParameters(new SecureRandom(), 3072, 256, 128);
    parameters.setName("Test Election");
    parameters.setNumberOfTellers(4);
    parameters.setThresholdTellers(3);

    final VerificatumHelper helper = new VerificatumHelper();
    assertThat(helper).isNotNull();

    final List<File> tellerInfoFiles = new ArrayList<>();

    // Create each teller.
    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerInfoFile = helper.createTeller(parameters, i, "localhost", 8080 + i, 4040 + i);
      assertThat(tellerInfoFile).isNotNull();

      tellerInfoFiles.add(tellerInfoFile);
    }

    // Copy the teller information files to each teller directory.
    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File tellerDirectory = VerificatumHelper.getTellerDirectory(parameters, i);
      assertThat(tellerDirectory).isNotNull();

      for (int j = 1; j <= parameters.getNumberOfTellers(); j++) {
        if (i != j) {
          final File source = tellerInfoFiles.get(j - 1);
          final File destination = new File(tellerDirectory, tellerInfoFiles.get(j - 1).getName());
          destination.delete();
          Files.copy(source.toPath(), destination.toPath());
        }
      }
    }

    // Make sure all the information files exist.
    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      final File[] files = helper.getTellerInformationFiles(parameters, i);

      for (final File file : files) {
        assertThat(file.exists()).isTrue();
      }
    }

    // Merge each teller.
    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      helper.mergeTeller(parameters, i);
    }

    // Create the election key pair on each teller in parallel.
    final ExecutorService createElectionKeyPairExecutor = Executors.newFixedThreadPool(parameters.getNumberOfTellers());

    final List<Callable<KeyPair>> createElectionKeyPairtasks = new ArrayList<>();
    IntStream.range(1, parameters.getNumberOfTellers() + 1).forEach(i -> {
      createElectionKeyPairtasks.add(() -> helper.createElectionKeyPair(parameters, i));
    });

    final List<Future<KeyPair>> createElectionKeyPairFutures = createElectionKeyPairExecutor.invokeAll(createElectionKeyPairtasks);
    createElectionKeyPairExecutor.shutdown();

    try {
      if (!createElectionKeyPairExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
        createElectionKeyPairExecutor.shutdownNow();
      }
    }
    catch (final InterruptedException e) {
      createElectionKeyPairExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Check that the key pair has been created.
    KeyPair keyPair = null;

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      keyPair = createElectionKeyPairFutures.get(i - 1).get();
      assertThat(keyPair).isNotNull();
      assertThat(keyPair.getPrivateKey()).isNull();
      assertThat(keyPair.getPublicKey()).isNotNull();

      if (i > 1) {
        final KeyPair lastKeyPair = createElectionKeyPairFutures.get(i - 2).get();
        assertThat(lastKeyPair.getPublicKey()).isEqualTo(keyPair.getPublicKey());
      }
    }

    // Create some ElGamal ciphertexts to be shuffled, mixed and decrypted.
    final ElGamalAlgorithmHelper elGamalAlgorithmHelper = new ElGamalAlgorithmHelper();
    final List<BigInteger> plainTexts = new ArrayList<>();
    final List<CipherText> cipherTexts = new ArrayList<>();
    final int numberOfValues = 10;

    for (int i = 1; i <= numberOfValues; i++) {
      final BigInteger plainText = parameters.getG().modPow(BigInteger.valueOf(i), parameters.getP());
      plainTexts.add(plainText);
      final byte[][] encrypted = elGamalAlgorithmHelper.encrypt(new SecureRandom(), parameters, keyPair, plainText.toByteArray());
      cipherTexts.add(new CipherText(encrypted[0]));
    }

    // Shuffle in parallel.
    final ExecutorService shuffleExecutor = Executors.newFixedThreadPool(parameters.getNumberOfTellers());

    final List<Callable<ProofWrapper<List<CipherText>>>> shuffleTasks = new ArrayList<>();
    IntStream.range(1, parameters.getNumberOfTellers() + 1).forEach(i -> {
      shuffleTasks.add(() -> helper.shuffle(parameters, i, 1, cipherTexts));
    });

    final List<Future<ProofWrapper<List<CipherText>>>> shuffleFutures = shuffleExecutor.invokeAll(shuffleTasks);
    shuffleExecutor.shutdown();

    try {
      if (!shuffleExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
        shuffleExecutor.shutdownNow();
      }
    }
    catch (final InterruptedException e) {
      shuffleExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Check that there are enough shuffled ciphertexts. We can't check anything else.
    ProofWrapper<List<CipherText>> shuffledCipherTexts = null;

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      shuffledCipherTexts = shuffleFutures.get(i - 1).get();
      assertThat(shuffledCipherTexts).isNotNull();
      assertThat(shuffledCipherTexts.getObject().size()).isEqualTo(cipherTexts.size());
      assertThat(shuffledCipherTexts.getProofFile().exists()).isTrue();
      shuffledCipherTexts.getProofFile().delete();
    }

    assertThat(shuffledCipherTexts).isNotNull();

    // Decrypt the shuffled ciphertexts in parallel.
    final ExecutorService decryptExecutor = Executors.newFixedThreadPool(parameters.getNumberOfTellers());
    final List<CipherText> shuffled = shuffledCipherTexts.getObject();

    final List<Callable<ProofWrapper<List<BigInteger>>>> decryptTasks = new ArrayList<>();
    IntStream.range(1, parameters.getNumberOfTellers() + 1).forEach(i -> {
      decryptTasks.add(() -> helper.decrypt(parameters, i, 1, shuffled));
    });

    final List<Future<ProofWrapper<List<BigInteger>>>> decryptFutures = decryptExecutor.invokeAll(decryptTasks);
    decryptExecutor.shutdown();

    try {
      if (!decryptExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
        decryptExecutor.shutdownNow();
      }
    }
    catch (final InterruptedException e) {
      decryptExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Check that there are enough decrypted plaintexts and that they all appear on the list of plaintexts (in a different order).
    ProofWrapper<List<BigInteger>> decryptedPlainTexts = null;

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      decryptedPlainTexts = decryptFutures.get(i - 1).get();
      assertThat(decryptedPlainTexts).isNotNull();
      assertThat(decryptedPlainTexts.getObject().size()).isEqualTo(cipherTexts.size());
      assertThat(decryptedPlainTexts.getProofFile().exists()).isTrue();
      decryptedPlainTexts.getProofFile().delete();
    }

    assertThat(decryptedPlainTexts).isNotNull();
    for (final BigInteger plainText : decryptedPlainTexts.getObject()) {
      assertThat(plainTexts).contains(plainText);
    }

    // Mix in parallel. We mix each ciphertext as a duplicate pair to test that thw width works.
    final ExecutorService mixExecutor = Executors.newFixedThreadPool(parameters.getNumberOfTellers());
    final int width = 2;
    final List<CipherText> duplicatedCipherTexts = new ArrayList<>();
    for (final CipherText cipherText : cipherTexts) {
      for (int i = 0; i < width; i++) {
        duplicatedCipherTexts.add(cipherText);
      }
    }

    final List<Callable<ProofWrapper<List<BigInteger>>>> mixTasks = new ArrayList<>();
    IntStream.range(1, parameters.getNumberOfTellers() + 1).forEach(i -> {
      mixTasks.add(() -> helper.mix(parameters, i, width, duplicatedCipherTexts));
    });

    final List<Future<ProofWrapper<List<BigInteger>>>> mixFutures = mixExecutor.invokeAll(mixTasks);
    mixExecutor.shutdown();

    try {
      if (!mixExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
        mixExecutor.shutdownNow();
      }
    }
    catch (final InterruptedException e) {
      mixExecutor.shutdownNow();
      Thread.currentThread().interrupt();
    }

    // Check that there are enough mixed plaintexts and that they all appear on the list of plaintexts (in a different order). Each plaintext should be duplicated.
    ProofWrapper<List<BigInteger>> mixedPlainTexts = null;

    for (int i = 1; i <= parameters.getNumberOfTellers(); i++) {
      mixedPlainTexts = mixFutures.get(i - 1).get();
      assertThat(mixedPlainTexts).isNotNull();
      assertThat(mixedPlainTexts.getObject().size()).isEqualTo(cipherTexts.size() * width);
      assertThat(mixedPlainTexts.getProofFile().exists()).isTrue();
      mixedPlainTexts.getProofFile().delete();
    }

    assertThat(mixedPlainTexts).isNotNull();
    for (int i = 0; i < mixedPlainTexts.getObject().size(); i += width) {
      final BigInteger plainText1 = mixedPlainTexts.getObject().get(i);
      assertThat(plainTexts).contains(plainText1);

      for (int j = 1; j < width; j++) {
        final BigInteger plainTextN = mixedPlainTexts.getObject().get(i + j);
        assertThat(plainText1).isEqualTo(plainTextN);
      }
    }
  }
}
