/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import com.fasterxml.jackson.annotation.JsonView;
import org.springframework.context.MessageSource;
import uk.co.pervasive_intelligence.vmv.BaseShellComponent;
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.ChaumPedersenAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.SchnorrAlgorithmHelper;

import java.io.File;
import java.math.BigInteger;
import java.net.InetAddress;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Selene implementation of the {@link CryptographyHelper}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class SeleneCryptographyHelper extends JavaCryptographyHelper {

  /** The maximum tracker number values. */
  static final int TRACKER_NUMBER_MAX = 99999999;

  /** The minimum tracker number values. */
  static final int TRACKER_NUMBER_MIN = 10000000;

  /** Chaum-Pedersen algorithm helper. */
  private final ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper;

  /** DSA algorithm helper. */
  private final DSAAlgorithmHelper dsaAlgorithmHelper;

  /** ElGamal algorithm helper. */
  private final ElGamalAlgorithmHelper elgamalAlgorithmHelper;

  /** Executor used for parallel processing. */
  private final ExecutorService executor = Executors.newWorkStealingPool();

  /** The source for messages. */
  private final MessageSource messageSource;

  /** Schnorr algorithm helper. */
  private final SchnorrAlgorithmHelper schnorrAlgorithmHelper;

  /** Verificatum helper. */
  private final VerificatumHelper verificatumHelper;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param messageSource                The source for messages.
   * @param dsaAlgorithmHelper           The DSA algorithm helper.
   * @param elgamalAlgorithmHelper       The ElGamal algorithm helper.
   * @param verificatumHelper            The Verificatum helper.
   * @param schnorrAlgorithmHelper       Schnorr algorithm helper.
   * @param chaumPedersenAlgorithmHelper Chaum-Pedersen algorithm helper.
   */
  public SeleneCryptographyHelper(final MessageSource messageSource, final DSAAlgorithmHelper dsaAlgorithmHelper,
                                  final ElGamalAlgorithmHelper elgamalAlgorithmHelper, final VerificatumHelper verificatumHelper,
                                  final SchnorrAlgorithmHelper schnorrAlgorithmHelper, final ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper) {
    this.messageSource = messageSource;
    this.dsaAlgorithmHelper = dsaAlgorithmHelper;
    this.elgamalAlgorithmHelper = elgamalAlgorithmHelper;
    this.verificatumHelper = verificatumHelper;
    this.schnorrAlgorithmHelper = schnorrAlgorithmHelper;
    this.chaumPedersenAlgorithmHelper = chaumPedersenAlgorithmHelper;
  }

  /**
   * Associates the voter identifier in the source list with the voter parameters in the destination list. The destionation list objects are updated.
   *
   * @param source      The source voter list.
   * @param destination The destination voter list.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public void associateVoters(final List<Voter> source, final List<Voter> destination) throws CryptographyException {
    if (source.size() != destination.size()) {
      throw new CryptographyException("Number of source and destination voters does not match: " + source.size() + " vs. " + destination.size());
    }

    // Perform the association.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.associate.voters_with_keys", new Object[] {source.size()}, null));

    // If public keys have been provided alongside the ids, then make sure the correct records are matched. Everything else is done with what remains in the order
    // provided. We only check the trapdoor public key. This assumes that all keys are unique.
    for (int i = 0; i < source.size(); i++) {
      final Voter sourceVoter = source.get(i);
      BigInteger trapdoorPublicKey = null;

      if ((sourceVoter.getVoterKeyPairs() != null) && (sourceVoter.getVoterKeyPairs().getTrapdoorKeyPair() != null)) {
        trapdoorPublicKey = sourceVoter.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey();
      }

      // Find the destination with the same public key, if appropriate.
      if (trapdoorPublicKey != null) {
        Voter destinationVoter = null;
        int j = 0;

        while ((destinationVoter == null) && (j < destination.size())) {
          if ((destination.get(j).getVoterKeyPairs() != null) &&
              (destination.get(j).getVoterKeyPairs().getTrapdoorKeyPair() != null) &&
              (destination.get(j).getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey() != null) &&
              (destination.get(j).getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey().equals(trapdoorPublicKey))) {
            destinationVoter = destination.get(j);
          }

          j++;
        }

        // If we've found a match, set the id.
        if (destinationVoter != null) {
          destinationVoter.setId(sourceVoter.getId());
        }
      }

      this.updateProgress(100 * (i + 1) / (float) source.size());
    }

    this.endProgress();

    // Now set all remaining ids in the order provided.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.associate.voters", new Object[] {source.size()}, null));
    int lastDestination = 0;

    for (int i = 0; i < source.size(); i++) {
      final Voter sourceVoter = source.get(i);
      Voter destinationVoter = null;
      int j = lastDestination;

      // If this id is not associated with a public key, find the next destination without an id.
      if ((sourceVoter.getVoterKeyPairs() == null) ||
          (sourceVoter.getVoterKeyPairs().getTrapdoorKeyPair() == null) ||
          (sourceVoter.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey() == null)) {
        while ((destinationVoter == null) && (j < destination.size())) {
          if ((destination.get(j).getId() == null)) {
            destinationVoter = destination.get(j);
          }

          j++;
        }
      }

      // Set the id.
      if (destinationVoter != null) {
        lastDestination = j;
        destinationVoter.setId(sourceVoter.getId());
      }

      this.updateProgress(100 * (i + 1) / (float) source.size());
    }

    this.endProgress();
  }

  /**
   * Checks that the teller parameters are correct for the election.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @throws CryptographyException if the parameters are incorrect.
   */
  private void checkTellers(final Parameters parameters, final int teller) throws CryptographyException {
    if (parameters.getNumberOfTellers() <= 0) {
      throw new CryptographyException("Cannot create teller when election is not using tellers");
    }

    if ((teller <= 0) || (teller > parameters.getNumberOfTellers())) {
      throw new CryptographyException("Incorrect teller number: must be in the range 1 to " + parameters.getNumberOfTellers());
    }
  }

  /**
   * Completes the formation of the commitments after the voting period has finished and updates the voter information with the remaining commitment values.
   *
   * @param parameters  The election parameters.
   * @param voters      The list of voters with their partial commitment values.
   * @param commitments The private commitment data from each teller.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public void completeCommitments(final Parameters parameters, final List<Voter> voters, final List<List<Commitment>> commitments) throws CryptographyException {
    int commitmentsSize = 0;
    for (final List<Commitment> list : commitments) {
      commitmentsSize = Math.max(commitmentsSize, list.size());
    }

    if (voters.size() != commitmentsSize) {
      throw new CryptographyException("Number of voters and commitments does not match: " + voters.size() + " vs. " + commitments.size());
    }

    // Create the alpha commitment values from all of the teller files. This assumes that the voters and partial commitments are in the same order, albeit we
    // check that the voter's public key matches.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.complete.commitment", new Object[] {voters.size()}, null));
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;

    for (int i = 0; i < voters.size(); i++) {
      final Voter voter = voters.get(i);

      // Form the product of all the g terms.
      BigInteger alpha = BigInteger.ONE;

      for (final List<Commitment> tellerCommitments : commitments) {
        BigInteger publicKey = null;

        if ((voter.getVoterKeyPairs() != null) && (voter.getVoterKeyPairs().getTrapdoorKeyPair() != null)) {
          publicKey = voter.getVoterKeyPairs().getTrapdoorKeyPair().getPublicKey();
        }

        if ((publicKey == null) || !publicKey.equals(tellerCommitments.get(i).getPublicKey())) {
          throw new CryptographyException("Voter's trapdoor public key (null " + (publicKey == null) + ") does not match commitment public key for voter " + i);
        }

        alpha = alpha.multiply(tellerCommitments.get(i).getG()).mod(wrapper.getP());
      }

      voter.setAlpha(alpha);
      this.updateProgress(100 * (i + 1) / (float) voters.size());
    }

    this.endProgress();
  }

  /**
   * Creates the commitment for a voter.
   *
   * @param parameters     The election parameters.
   * @param keyPair        The election key pair.
   * @param voterPublicKey The voter's public encryption key.
   * @param random         The random value used to create the commitment.
   * @return An array of objects: the commitment and the random values used to encrypt the g and h terms.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  private Object[] createCommitment(final Parameters parameters, final KeyPair keyPair, final BigInteger voterPublicKey, final BigInteger random) throws CryptographyException {
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();

    // Create the h and g terms (referred to as b and a in the Selene appendix).
    final BigInteger b = voterPublicKey.modPow(random, p); // b = h^random.
    final BigInteger a = wrapper.getG().modPow(random, p); // a = g^random.

    final byte[][] encryptedH = this.elgamalAlgorithmHelper.encrypt(this.getRandom(), parameters, keyPair, b.toByteArray());
    final byte[][] encryptedG = this.elgamalAlgorithmHelper.encrypt(this.getRandom(), parameters, keyPair, a.toByteArray());

    final Commitment commitment = new Commitment();
    commitment.setPublicKey(voterPublicKey);
    commitment.setH(b);
    commitment.setG(a);
    commitment.setEncryptedH(encryptedH[0]);
    commitment.setEncryptedG(encryptedG[0]);

    return new Object[] {commitment, encryptedG[1], encryptedH[1]};
  }

  /**
   * Creates the non-interactive zero-knowledge proofs of knowledge of a commitment for a voter.
   *
   * @param parameters        The election parameters.
   * @param keyPair           The election key pair.
   * @param voterPublicKey    The voter's public encryption key.
   * @param random            The random value used to create the commitment.
   * @param commitment        The voter's commitment.
   * @param encryptionSecretG The random value used to encrypt the commitment g value.
   * @param encryptionSecretH The random value used to encrypt the commitment h value.
   * @return The commitment proofs.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  private CommitmentProof createCommitmentProof(final Parameters parameters, final KeyPair keyPair, final BigInteger voterPublicKey, final BigInteger random,
                                                final Commitment commitment, final BigInteger encryptionSecretG, final BigInteger encryptionSecretH) throws CryptographyException {
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();
    final BigInteger q = wrapper.getQ();
    final BigInteger g = wrapper.getG();

    // Form the statements.
    final CipherText cipherTextG = new CipherText(commitment.getEncryptedG()); // (A1, A2).
    final CipherText cipherTextH = new CipherText(commitment.getEncryptedH()); // (B1, B2).

    // pi11 = NIZK2.Prove(A1; g; s1) where s1 is the encryptionSecretG.
    final Proof pi11 = this.schnorrAlgorithmHelper.generateProof(this.getRandom(), parameters, encryptionSecretG, new Statement(cipherTextG.getAlpha(), g));

    // pi12 = NIZK2.Prove(B1; g; s2) where s2 is the encryptionSecretH.
    final Proof pi12 = this.schnorrAlgorithmHelper.generateProof(this.getRandom(), parameters, encryptionSecretH, new Statement(cipherTextH.getAlpha(), g));

    // Choose random element t in q.
    final BigInteger t = new BigInteger(q.bitLength(), this.getRandom()).mod(q);

    // Compute (A1', A2') = (A1^t, A2^t) mod p; (B1', B2') = (B1^t, B2^t) mod p.
    final BigInteger a1Dash = cipherTextG.getAlpha().modPow(t, p);
    final BigInteger a2Dash = cipherTextG.getBeta().modPow(t, p);
    final BigInteger b1Dash = cipherTextH.getAlpha().modPow(t, p);
    final BigInteger b2Dash = cipherTextH.getBeta().modPow(t, p);

    // pi21 = NIZK1.Prove(A1Dash, A1; A2Dash, A2; t).
    final Proof pi21 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, t,
        new Statement(a1Dash, cipherTextG.getAlpha()), new Statement(a2Dash, cipherTextG.getBeta()));

    // pi22 = NIZK1.Prove(B1Dash, B1; B2Dash, B2; t).
    final Proof pi22 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, t,
        new Statement(b1Dash, cipherTextH.getAlpha()), new Statement(b2Dash, cipherTextH.getBeta()));

    // pi23 = NIZK1.Prove(B1Dash, B1; B2Dash, B2; t).
    final Proof pi23 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, t,
        new Statement(a1Dash, cipherTextG.getAlpha()), new Statement(b1Dash, cipherTextH.getAlpha()));

    // Compute C = a^t mod p; D = b^t mod p, where a = g^random and b = h^random.
    final BigInteger c = commitment.getG().modPow(t, p);
    final BigInteger d = commitment.getH().modPow(t, p);

    // pi31 = NIZK1.Prove(A1Dash, g; A2Dash * C^-1 mod p, electionPublicKey; s1 * t mod q).
    final Proof pi31 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, encryptionSecretG.multiply(t).mod(q),
        new Statement(a1Dash, g), new Statement(a2Dash.multiply(c.modPow(BigInteger.ONE.negate(), p)).mod(p), keyPair.getPublicKey()));

    // pi32 = NIZK1.Prove(B1Dash, g; B2Dash * D^-1 mod p, electionPublicKey; s2 * t).
    final Proof pi32 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, encryptionSecretH.multiply(t).mod(q),
        new Statement(b1Dash, g), new Statement(b2Dash.multiply(d.modPow(BigInteger.ONE.negate(), p)).mod(p), keyPair.getPublicKey()));

    // pi4 = NIZK1.Prove(C, g; D, voterPublicKey; r * t mod q). Note the witness is not t as provided in the paper.
    final BigInteger modRandom = random.multiply(t).mod(q);
    final Proof pi4 = this.chaumPedersenAlgorithmHelper.generateProof(this.getRandom(), parameters, modRandom, new Statement(c, g), new Statement(d,
        voterPublicKey));

    // pi5 = NIZK2.Prove(C, g; r * t mod q).
    final Proof pi5 = this.schnorrAlgorithmHelper.generateProof(this.getRandom(), parameters, modRandom, new Statement(c, g));

    // Output the proof pi = (A1', A2', B1', B2', C, D, pi11, pi12, pi21, pi22, pi23, pi31, pi32, pi4, pi5).
    return new CommitmentProof(a1Dash, a2Dash, b1Dash, b2Dash, c, d, pi11, pi12, pi21, pi22, pi23, pi31, pi32, pi4, pi5);
  }

  /**
   * Uses the list of voter key pairs and tracker numbers and creates the corresponding encrypted commitments for them. Note that the returned list of commitments
   * is assumed to be in the same order as the voter key pairs and the tracker numbers - these have effectively associated in order from this point onwards.
   *
   * @param parameters     The election parameters.
   * @param keyPair        The election key pair.
   * @param votersKeyPairs The list of voter key pairs.
   * @param trackerNumbers The shuffled list of public tracker numbers.
   * @return The encrypted commitment values and the corresponding proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public ProofWrapper<List<Commitment>> createCommitments(final Parameters parameters, final KeyPair keyPair, final List<VoterKeyPairs> votersKeyPairs,
                                                          final List<TrackerNumber> trackerNumbers) throws CryptographyException {
    if (votersKeyPairs.size() != trackerNumbers.size()) {
      throw new CryptographyException("Number of voter key pairs and tracker numbers does not match: " + votersKeyPairs.size() + " vs. " + trackerNumbers.size());
    }

    // Create the encrypted tracker number commitments.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.create.commitments", new Object[] {trackerNumbers.size()}, null));
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();
    final List<Commitment> commitments = new ArrayList<>();
    final List<CommitmentProof> commitmentProofs = new ArrayList<>();


    // The commitments are created across tellers, but if there are no tellers, this is the same process as for the local teller. Either way, execute the creation
    // in parallel.
    try {
      final List<Callable<Object[]>> createCommitmentsTasks = new ArrayList<>();
      IntStream.range(0, votersKeyPairs.size()).forEach(i -> createCommitmentsTasks.add(() -> {
        // Create a random value (mod p) and use it to create the commitment.
        final BigInteger random = new BigInteger(wrapper.getL(), this.getRandom()).mod(p);
        final BigInteger voterPublicKey = votersKeyPairs.get(i).getTrapdoorKeyPair().getPublicKey();
        final Object[] commitmentValues = this.createCommitment(parameters, keyPair, voterPublicKey, random);
        final Commitment commitment = (Commitment) commitmentValues[0];

        // Create the corresponding proofs of knowledge on the commitments. This requires the random value used during the encryption.
        final BigInteger encryptionSecretG = new BigInteger(1, (byte[]) commitmentValues[1]);
        final BigInteger encryptionSecretH = new BigInteger(1, (byte[]) commitmentValues[2]);
        final CommitmentProof commitmentProof = this.createCommitmentProof(parameters, keyPair, voterPublicKey, random, commitment, encryptionSecretG,
            encryptionSecretH);

        // Verify proofs before proceeding as a sanity check.
        if (!this.verifyCommitmentProof(parameters, keyPair, voterPublicKey, commitment, commitmentProof)) {
          throw new CryptographyException("Could not verify commitment proofs for voter: " + i);
        }

        return new Object[] {commitment, commitmentProof};
      }));

      final List<Future<Object[]>> createCommitmentsFutures = this.executor.invokeAll(createCommitmentsTasks);

      for (int i = 0; i < votersKeyPairs.size(); i++) {
        final Object[] results = createCommitmentsFutures.get(i).get();
        final Commitment commitment = (Commitment) results[0];
        final CommitmentProof commitmentProof = (CommitmentProof) results[1];

        commitments.add(commitment);
        commitmentProofs.add(commitmentProof);

        this.updateProgress(100 * (i + 1) / (float) votersKeyPairs.size());
      }
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not execute create commitments in parallel", e);
    }

    // Create the proof CSV file.
    final File proofFile = this.writeCSVToFile(CommitmentProof.class, commitmentProofs, JacksonViews.Public.class);

    this.endProgress();

    return new ProofWrapper<>(commitments, proofFile);
  }

  /**
   * Creates the election key pair using the created parameters.
   *
   * @param parameters Key generation parameters.
   * @param options    Key parameter options.
   * @return The created key pair.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public KeyPair createElectionKeyPair(final Parameters parameters, final Object... options) throws CryptographyException {
    if (parameters.getNumberOfTellers() > 0) {
      this.checkTellers(parameters, (Integer) options[0]);
    }

    this.startProgress(this.messageSource.getMessage("cryptography.selene.create.election.keys", null, null));

    // If no tellers are being used, create the keys locally. Otherwise use Verificatum.
    final KeyPair keyPair;

    if (parameters.getNumberOfTellers() <= 0) {
      keyPair = this.dsaAlgorithmHelper.createKeys(this.getRandom(), parameters);
    }
    else {
      keyPair = this.verificatumHelper.createElectionKeyPair(parameters, (Integer) options[0]);
    }

    this.endProgress();

    return keyPair;
  }

  /**
   * Creates the election parameters using the required options.
   *
   * @param options Key parameter options.
   * @return The created parameters.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public Parameters createElectionParameters(final Object... options) throws CryptographyException {
    this.startProgress(this.messageSource.getMessage("cryptography.selene.create.election.parameters", options, null));
    final Parameters parameters = this.dsaAlgorithmHelper.createParameters(this.getRandom(), options);
    this.endProgress();

    return parameters;
  }

  /**
   * Creates the non-interactive zero-knowledge proofs of knowledge of an ElGamal encryption.
   *
   * @param parameters       The election parameters.
   * @param keyPair          The election key pair.
   * @param plainText        The plaintext that was encrypted.
   * @param encrypted        The encrypted value.
   * @param signatureKeyPair The voter's signing key pair used for the encrypted vote signature.
   * @param signature        The signature over the encrypted vote.
   * @param encryptionSecret The random value used to encrypt the plaintext value.
   * @return The encryption proof.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  EncryptProof createEncryptProof(final Parameters parameters, final KeyPair keyPair, final BigInteger plainText, final byte[] encrypted,
                                  final KeyPair signatureKeyPair, final byte[] signature, final BigInteger encryptionSecret) throws CryptographyException {
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();
    final BigInteger q = wrapper.getQ();
    final BigInteger g = wrapper.getG();

    // Extract the ciphertext values.
    final CipherText cipherText = new CipherText(encrypted); // (c1, c2).

    // Choose a random message in G and and exponent in Zq.
    final BigInteger random = new BigInteger(p.bitLength(), this.getRandom()).mod(p);
    final BigInteger randomMessage = g.modPow(random, p); // Use the random number to get an element in the group using the generator g.
    final BigInteger randomExponent = new BigInteger(q.bitLength(), this.getRandom()).mod(q);

    // Compute cR1 = g^randomExponent.
    final BigInteger cR1 = g.modPow(randomExponent, p);

    // Compute cR2 = publicKey^randomExponent * randomMessage.
    final BigInteger cR2 = keyPair.getPublicKey().modPow(randomExponent, p).multiply(randomMessage).mod(p);

    // Form the hash c = H(c1, c2, cR1, cR2, vk, p, q).
    final BigInteger c = this.hash(q.bitLength(), cipherText.getAlpha(), cipherText.getBeta(), cR1, cR2, signatureKeyPair.getPublicKey(), p, q);

    // Compute mBar = m^c * randomMessage.
    final BigInteger mBar = plainText.modPow(c, p).multiply(randomMessage).mod(p);

    // Compute kBar = encryptionSecret * c + randomExponent.
    final BigInteger kBar = encryptionSecret.multiply(c).add(randomExponent).mod(q);

    // Compute c1Bar = g^kBar.
    final BigInteger c1Bar = g.modPow(kBar, p);

    // Compute c2Bar = publicKey^kBar * mBar.
    final BigInteger c2Bar = keyPair.getPublicKey().modPow(kBar, p).multiply(mBar).mod(p);

    // Output the proof (c, cR1, cR2, c1Bar, c2Bar, s).
    return new EncryptProof(cR1, cR2, c1Bar, c2Bar, signature);
  }

  /**
   * Creates key pairs using the required key generation parameters.
   *
   * @param name       The name of the progress item.
   * @param number     The number of key pairs.
   * @param parameters Key generation parameters.
   * @return The required number of created key pairs.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  private List<KeyPair> createKeyPairs(final String name, final int number, final Parameters parameters) throws CryptographyException {
    final List<KeyPair> keyPairs = new ArrayList<>();

    try {
      // Execute the creation of keys in parallel.
      this.startProgress(name);
      final List<Callable<KeyPair>> createKeysTasks = new ArrayList<>();
      IntStream.range(0, number).forEach(i -> createKeysTasks.add(() -> this.dsaAlgorithmHelper.createKeys(this.getRandom(), parameters)));

      final List<Future<KeyPair>> createKeysFutures = this.executor.invokeAll(createKeysTasks);

      for (int i = 0; i < number; i++) {
        keyPairs.add(createKeysFutures.get(i).get());
        this.updateProgress(100 * (i + 1) / (float) number);
      }
      this.endProgress();
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not execute create keys in parallel", e);
    }

    return keyPairs;
  }

  /**
   * Creates a Verificatum teller, returning its information file which should be shared with all other tellers.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @param ip         The teller's ip address (or DNS host name).
   * @param tellerPort The teller's main port.
   * @param hintPort   The teller's hint port.
   * @return The path to the teller's information file which needs to be copied to all tellers.
   * @throws CryptographyException if the teller could not be setup.
   */
  @Override
  public File createTeller(final Parameters parameters, final int teller, final String ip, final int tellerPort, final int hintPort) throws CryptographyException {
    this.checkTellers(parameters, teller);

    // Create the main teller URL using the locally obtained IP address, if needed.
    try {
      String hostAddress = ip;

      if (DEFAULT_TELLER_IP.equals(hostAddress)) {
        hostAddress = InetAddress.getLocalHost().getHostAddress();
      }

      this.startProgress(this.messageSource.getMessage("cryptography.selene.create.teller",
          new Object[] {teller, parameters.getNumberOfTellers(), hostAddress, tellerPort, hintPort}, null));
      final File tellerInformationFile = this.verificatumHelper.createTeller(parameters, teller, hostAddress, tellerPort, hintPort);
      this.endProgress();

      return tellerInformationFile;
    }
    catch (final CryptographyException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not form teller address", e);
    }
  }

  /**
   * Creates the required tracker numbers. Tracker numbers are guaranteed to be positive and unique.
   *
   * @param parameters The election parameters.
   * @param keyPair    The election key pair.
   * @param number     The number to create.
   * @return The set of tracker numbers.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public Set<TrackerNumber> createTrackerNumbers(final Parameters parameters, final KeyPair keyPair, final int number) throws CryptographyException {
    this.startProgress(this.messageSource.getMessage("cryptography.selene.create.tracker_numbers", new Object[] {number}, null));

    // Create the tracker number as its associated values.
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;

    // First create the required number of unique tracker numbers.
    final Set<Integer> values = new HashSet<>();

    while (values.size() < number) {
      values.add(this.getRandom().nextInt(TRACKER_NUMBER_MAX - TRACKER_NUMBER_MIN + 1) + TRACKER_NUMBER_MIN);
    }

    // Now convert them into numbers in the group.
    final List<Integer> orderedValues = new ArrayList<>(values);
    final List<BigInteger> orderedGroupValues = new ArrayList<>();

    for (int i = 0; i < number; i++) {
      orderedGroupValues.add(wrapper.getG().modPow(BigInteger.valueOf(orderedValues.get(i)), wrapper.getP()));
    }

    // Now encrypt each of the tracker numbers in parallel...
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();

    try {
      final List<Callable<byte[]>> createTrackerNumbersTasks = new ArrayList<>();
      IntStream.range(0, number).forEach(i -> createTrackerNumbersTasks.add(() -> this.elgamalAlgorithmHelper.encrypt(this.getRandom(), parameters, keyPair,
          orderedGroupValues.get(i).toByteArray())[0]));

      final List<Future<byte[]>> createTrackerNumbersFutures = this.executor.invokeAll(createTrackerNumbersTasks);

      // ...and form the resulting objects.
      for (int i = 0; i < number; i++) {
        trackerNumbers.add(new TrackerNumber(orderedValues.get(i), orderedGroupValues.get(i), createTrackerNumbersFutures.get(i).get()));
        this.updateProgress(100 * trackerNumbers.size() / (float) number);
      }
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not execute create tracker numbers in parallel", e);
    }

    this.endProgress();

    return trackerNumbers;
  }

  /**
   * Creates key pairs for all voters using the required election parameters.
   *
   * @param voters     The number of voters.
   * @param parameters Key generation parameters.
   * @return A created key pairs per voter.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public List<VoterKeyPairs> createVotersKeyPairs(final int voters, final Parameters parameters) throws CryptographyException {
    // Create the trapdoor and signing key pairs.
    final List<KeyPair> trapdoor = this.createKeyPairs(this.messageSource.getMessage("cryptography.selene.create.voter.trapdoor.keys",
        new Object[] {voters}, null), voters, parameters);
    final List<KeyPair> signing = this.createKeyPairs(this.messageSource.getMessage("cryptography.selene.create.voter.signing.keys",
        new Object[] {voters}, null), voters, parameters);

    // Merge the two lists together.
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();

    for (int i = 0; i < trapdoor.size(); i++) {
      keyPairs.add(new VoterKeyPairs(trapdoor.get(i), signing.get(i)));
    }

    return keyPairs;
  }

  /**
   * Decrypts the commitments and forms the final association between each voter key pair, tracker number and commitment, returning the voter information.
   *
   * @param parameters     The election parameters.
   * @param keyPair        The election key pair.
   * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
   * @param votersKeyPairs The list of voter key pairs.
   * @param trackerNumbers The shuffled list of public tracker numbers.
   * @param commitments    The encrypted commitments from each teller.
   * @return The consolidated list of voter data ready to be associated with voters and the corresponding proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public ProofWrapper<List<Voter>> decryptCommitments(final Parameters parameters, final KeyPair keyPair, final int teller,
                                                      final List<VoterKeyPairs> votersKeyPairs, final List<TrackerNumber> trackerNumbers,
                                                      final List<List<Commitment>> commitments) throws CryptographyException {
    int commitmentsSize = 0;
    for (final List<Commitment> list : commitments) {
      commitmentsSize = Math.max(commitmentsSize, list.size());
    }

    if ((votersKeyPairs.size() != trackerNumbers.size()) || (votersKeyPairs.size() != commitmentsSize)) {
      throw new CryptographyException("Number of voter key pairs, tracker numbers or commitments does not match: " + votersKeyPairs.size() + " vs. "
          + trackerNumbers.size() + " vs. " + commitments.size());
    }

    if (parameters.getNumberOfTellers() > 0) {
      this.checkTellers(parameters, teller);
    }

    // Form the commitment values from all of the teller files. We assume that all teller files have been supplied and that the commitments are in the same order,
    // albeit we check that the voter's public key matches.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.decrypt.form", new Object[] {trackerNumbers.size()}, null));
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final List<CipherText> combined = new ArrayList<>();

    for (int i = 0; i < votersKeyPairs.size(); i++) {
      // Form the product of all the encrypted h terms, checking that each commitment has the same trapdoor public key as expected for the voter.
      BigInteger alphaProduct = BigInteger.ONE;
      BigInteger betaProduct = BigInteger.ONE;

      for (final List<Commitment> tellerCommitments : commitments) {
        BigInteger publicKey = null;

        if ((votersKeyPairs.get(i) != null) && (votersKeyPairs.get(i).getTrapdoorKeyPair() != null)) {
          publicKey = votersKeyPairs.get(i).getTrapdoorKeyPair().getPublicKey();
        }

        if ((publicKey == null) || !publicKey.equals(tellerCommitments.get(i).getPublicKey())) {
          throw new CryptographyException("Voter's trapdoor public key (null " + (publicKey == null) + ") does not match commitment public key for voter " + i);
        }

        final CipherText commitmentCipherText = new CipherText(tellerCommitments.get(i).getEncryptedH());
        alphaProduct = alphaProduct.multiply(commitmentCipherText.getAlpha()).mod(wrapper.getP());
        betaProduct = betaProduct.multiply(commitmentCipherText.getBeta()).mod(wrapper.getP());
      }

      // Multiple with the voter's encrypted tracker number.
      final CipherText trackerNumberCipherText = new CipherText(trackerNumbers.get(i).getEncryptedTrackerNumberInGroup());
      alphaProduct = alphaProduct.multiply(trackerNumberCipherText.getAlpha()).mod(wrapper.getP());
      betaProduct = betaProduct.multiply(trackerNumberCipherText.getBeta()).mod(wrapper.getP());

      // Form the combined value.
      combined.add(new CipherText(alphaProduct, betaProduct));
      this.updateProgress(100 * (i + 1) / (float) votersKeyPairs.size());
    }

    this.endProgress();

    // Decrypt the resulting combined values. If no tellers are being used, decrypt locally. Otherwise use Verificatum.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.decrypt.commitments", new Object[] {trackerNumbers.size()}, null));
    final List<BigInteger> decryptedCommitments;
    final File proofFile;

    if (parameters.getNumberOfTellers() <= 0) {
      decryptedCommitments = new ArrayList<>();

      for (int i = 0; i < votersKeyPairs.size(); i++) {
        final byte[] decrypted = this.elgamalAlgorithmHelper.decrypt(parameters, keyPair, combined.get(i).toByteArray());
        decryptedCommitments.add(new BigInteger(1, decrypted));
        this.updateProgress(100 * (i + 1) / (float) votersKeyPairs.size());
      }

      // Create an empty proof file.
      try {
        proofFile = Files.createTempFile(null, null).toFile();
      }
      catch (final Exception e) {
        throw new CryptographyException("Could not create empty proof file", e);
      }
    }
    else {
      // Verificatum decryption with proof file. Extract the encrypted values, decrypt them and then convert back into plaintext values.
      final ProofWrapper<List<BigInteger>> decrypted = this.verificatumHelper.decrypt(parameters, teller, 1, combined);
      decryptedCommitments = decrypted.getObject();
      proofFile = decrypted.getProofFile();
    }

    this.endProgress();

    // Form the association between the voter key pairs, encrypted tracker numbers and decrypted commitments.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.decrypt.allocate", new Object[] {trackerNumbers.size()}, null));
    final List<Voter> voters = new ArrayList<>();

    for (int i = 0; i < votersKeyPairs.size(); i++) {
      final Voter voter = new Voter();
      voter.setVoterKeyPairs(votersKeyPairs.get(i));
      voter.setTrackerNumber(trackerNumbers.get(i));
      voter.setBeta(decryptedCommitments.get(i));
      voters.add(voter);
      this.updateProgress(100 * (i + 1) / (float) votersKeyPairs.size());
    }

    this.endProgress();

    return new ProofWrapper<>(voters, proofFile);
  }

  /**
   * Uses an alpha and beta to obtain the decrypted tracker number for a voter given their public encryption key.
   *
   * @param parameters     The election parameters.
   * @param alpha          The alpha commitment.
   * @param beta           The beta commitment.
   * @param publicKey      The voter's public encryption key.
   * @param votersKeyPairs The voters' private and public keys.
   * @param trackerNumbers The tracker numbers including their restricted elements.
   * @return The corresponding plaintext tracker number, if available.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public TrackerNumber decryptTrackerNumber(final Parameters parameters, final BigInteger alpha, final BigInteger beta, final BigInteger publicKey,
                                            final List<VoterKeyPairs> votersKeyPairs, final List<TrackerNumber> trackerNumbers) throws CryptographyException {
    // Attempt to find the encryption key pair for the voter using their public key.
    KeyPair keyPair = null;
    int i = 0;

    while ((keyPair == null) && (i < votersKeyPairs.size())) {
      if (votersKeyPairs.get(i).getTrapdoorKeyPair().getPublicKey().equals(publicKey)) {
        keyPair = votersKeyPairs.get(i).getTrapdoorKeyPair();
      }
      i++;
    }

    if (keyPair == null) {
      throw new CryptographyException("Could not find voter's key pair for public key: " + publicKey);
    }

    // Attempt to decrypt the alpha and beta commitments to obtain the tracker number in the group.
    final byte[] decrypted = this.elgamalAlgorithmHelper.decrypt(parameters, keyPair, new CipherText(alpha, beta).toByteArray());
    final BigInteger trackerNumberInGroup = new BigInteger(1, decrypted);

    // Attempt to find the corresponding tracker number.
    TrackerNumber trackerNumber = null;
    i = 0;

    while ((trackerNumber == null) && (i < trackerNumbers.size())) {
      if (trackerNumbers.get(i).getTrackerNumberInGroup().equals(trackerNumberInGroup)) {
        trackerNumber = trackerNumbers.get(i);
      }
      i++;
    }

    if (trackerNumber == null) {
      throw new CryptographyException("Could not find tracker number from tracker number in group: " + trackerNumberInGroup);
    }

    return trackerNumber;
  }

  /**
   * Encrypts and signs the plaintext votes for every voter. The voter list is updated to include the encrypted vote and this list is also returned together with
   * the proof of knowledge.
   *
   * @param parameters       The election parameters.
   * @param keyPair          The election key pair.
   * @param votersKeyPairs   The list of voter key pairs.
   * @param voteOptions      The list of vote options.
   * @param voters           The list of voters with their plaintext votes.
   * @param ersEncryptProofs The optional list of encryption proofs which go alongside prior encrypted votes.
   * @return The encrypted list of voter data and the corresponding proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public ProofWrapper<List<Voter>> encryptVotes(final Parameters parameters, final KeyPair keyPair, final List<VoterKeyPairs> votersKeyPairs,
                                                final List<VoteOption> voteOptions, final List<Voter> voters, final List<EncryptProof> ersEncryptProofs) throws CryptographyException {
    if (votersKeyPairs.size() < voters.size()) {
      throw new CryptographyException("Number of voter key pairs insufficient for voters: " + votersKeyPairs.size() + " vs. " + voters.size());
    }

    // Encrypt and sign each vote, ignoring blanks and those votes which have already been encrypted.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.encrypt.votes", new Object[] {voters.size()}, null));
    final List<EncryptProof> encryptProofs = new ArrayList<>();
    final Set<String> encryptedVotes = new HashSet<>();
    int expectedVotes = 0;

    try {
      final List<Callable<Object[]>> encryptVotesTasks = new ArrayList<>();
      IntStream.range(0, voters.size()).forEach(i -> encryptVotesTasks.add(() -> {
        final Voter voter = voters.get(i);

        // Find any existing encrypted vote, signature and proof.
        byte[] encryptedVote = (voter != null) ? voter.getEncryptedVote() : null;
        encryptedVote = (encryptedVote != null) && (encryptedVote.length <= 0) ? null : encryptedVote;

        byte[] encryptedVoteSignature = (voter != null) ? voter.getEncryptedVoteSignature() : null;
        encryptedVoteSignature = (encryptedVoteSignature != null) && (encryptedVoteSignature.length <= 0) ? null : encryptedVoteSignature;

        EncryptProof encryptProof = null;

        // Find the corresponding proof using the signature.
        if (encryptedVoteSignature != null) {
          final byte[] searchSignature = encryptedVoteSignature;

          encryptProof = ersEncryptProofs.stream()
              .filter(proof -> (proof != null) && Arrays.equals(proof.getEncryptedVoteSignature(), searchSignature))
              .findAny().orElse(null);
        }

        if ((encryptedVote != null) && ((encryptedVoteSignature == null) || (encryptProof == null))) {
          throw new CryptographyException("Missing signature or proof for encrypted vote for voter " + voter.getId());
        }

        // If we need to encrypt, then do not encrypt or sign blank votes. Correspondingly, no proof gets generated.
        if ((encryptedVote == null) && (voter != null) && (voter.getPlainTextVote() != null) && (voter.getPlainTextVote().trim().length() > 0)) {
          // We need to encrypt, then find the relevant keys and perform the encryption, signing and proof generation.
          final BigInteger signaturePublicKey;

          if ((voter.getVoterKeyPairs() != null) && (voter.getVoterKeyPairs().getSignatureKeyPair() != null)) {
            signaturePublicKey = voter.getVoterKeyPairs().getSignatureKeyPair().getPublicKey();
          }
          else {
            signaturePublicKey = null;
          }

          if (signaturePublicKey == null) {
            throw new CryptographyException("Missing signature key pair for voter " + voter.getId());
          }

          // Find the voter's private signing key using the their public key.
          final VoterKeyPairs voterKeyPairs = votersKeyPairs.stream()
              .filter(pair -> signaturePublicKey.equals(((pair != null) && (pair.getSignatureKeyPair() != null)) ? pair.getSignatureKeyPair().getPublicKey() :
                  null))
              .findAny().orElse(null);

          if ((voterKeyPairs == null) || (voterKeyPairs.getSignatureKeyPair() == null) || (voterKeyPairs.getSignatureKeyPair().getPrivateKey() == null)) {
            throw new CryptographyException("Could not find signature key pair or signature private key for voter " + voter.getId());
          }

          // Find the corresponding vote option.
          final VoteOption voteOption = voteOptions.stream()
              .filter(option -> voter.getPlainTextVote().equals(option.getOption()))
              .findAny().orElse(null);

          if (voteOption == null) {
            throw new CryptographyException("Plaintext vote for voter " + voter.getId() + " does not match one of the available vote options " + voter.getPlainTextVote());
          }

          // Encrypt and sign their plaintext vote as a vote option. We also convert the encrypted vote into a string and put it in the encrypted votes set.
          final byte[][] encryptedVoteCiphers = this.elgamalAlgorithmHelper.encrypt(this.getRandom(), parameters, keyPair,
              voteOption.getOptionNumberInGroup().toByteArray());
          encryptedVote = encryptedVoteCiphers[0];
          encryptedVoteSignature = this.dsaAlgorithmHelper.sign(parameters, voterKeyPairs.getSignatureKeyPair(), encryptedVoteCiphers[0]);

          // Create the corresponding proof of knowledge of the encryption. This requires the random value used during the encryption.
          final BigInteger encryptionSecret = new BigInteger(1, encryptedVoteCiphers[1]);
          encryptProof = this.createEncryptProof(parameters, keyPair, voteOption.getOptionNumberInGroup(), encryptedVoteCiphers[0],
              voterKeyPairs.getSignatureKeyPair(), encryptedVoteSignature, encryptionSecret);

          // Verify proof before proceeding as a sanity check.
          if (!this.verifyEncryptProof(parameters, keyPair, encryptedVoteCiphers[0], voterKeyPairs.getSignatureKeyPair(), encryptProof)) {
            throw new CryptographyException("Could not verify encryption proofs for voter: " + i);
          }
        }

        return new Object[] {encryptedVote, encryptedVoteSignature, encryptProof};
      }));

      final List<Future<Object[]>> encryptVotesFutures = this.executor.invokeAll(encryptVotesTasks);

      // Extract the results.
      for (int i = 0; i < voters.size(); i++) {
        final Object[] results = encryptVotesFutures.get(i).get();
        final byte[] encryptedVote = (byte[]) results[0];
        final byte[] encryptedVoteSignature = (byte[]) results[1];
        final EncryptProof encryptProof = (EncryptProof) results[2];

        // We may not have an encrypted vote, which is normal if there was no vote.
        if ((encryptedVote != null) && (encryptedVoteSignature != null) && (encryptProof != null)) {
          expectedVotes++;

          final Voter voter = voters.get(i);
          encryptedVotes.add(Base64.getEncoder().encodeToString(encryptedVote));
          voter.setEncryptedVote(encryptedVote);
          voter.setEncryptedVoteSignature(encryptedVoteSignature);
          encryptProofs.add(encryptProof);
        }

        this.updateProgress(100 * (i + 1) / (float) voters.size());
      }
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not execute encrypt votes in parallel", e);
    }

    // To check that each encrypted vote is unique, we just need to check that the number of encrypted votes (Base 64 encoded strings) in the encrypted vote set
    // has the same number as the number of expected votes.
    if (encryptedVotes.size() != expectedVotes) {
      throw new CryptographyException("Found duplicate encrypted votes");
    }

    // Create the proof CSV file.
    final File proofFile = this.writeCSVToFile(EncryptProof.class, encryptProofs, JacksonViews.Public.class);

    this.endProgress();

    return new ProofWrapper<>(voters, proofFile);
  }

  /**
   * @return The class used for the election parameters.
   */
  @Override
  public Class<? extends Parameters> getElectionParametersClass() {
    return this.dsaAlgorithmHelper.getParametersClass();
  }

  /**
   * Gets the array of local teller information files in order for all tellers. The files are assumed to be held within the specified teller directory.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The array of local teller information files.
   * @throws CryptographyException if incorrect teller information is provided.
   */
  @Override
  public File[] getTellerInformationFiles(final Parameters parameters, final int teller) throws CryptographyException {
    this.checkTellers(parameters, teller);

    return this.verificatumHelper.getTellerInformationFiles(parameters, teller);
  }

  /**
   * Maps the list of vote options to numbers in the election parameter group. The list of vote options is modified to contain the mapping.
   *
   * @param parameters  The election parameters.
   * @param voteOptions The vote options to map.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public void mapVoteOptions(final Parameters parameters, final List<VoteOption> voteOptions) throws CryptographyException {
    // Check that all pre-assigned option numbers in the group are unique.
    final long preAssignedCount = voteOptions.stream()
        .filter(voteOption -> voteOption.getOptionNumberInGroup() != null)
        .count();
    final Set<BigInteger> optionNumbersInGroup = voteOptions.stream()
        .filter(voteOption -> voteOption.getOptionNumberInGroup() != null)
        .map(VoteOption::getOptionNumberInGroup)
        .collect(Collectors.toSet());

    if (optionNumbersInGroup.size() != preAssignedCount) {
      throw new CryptographyException("Pre-assigned option numbers in the group are not unique");
    }

    // Allocate unique option numbers in the group to all of the vote options, keeping any that have already been assigned.
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final int number = voteOptions.size();

    this.startProgress(this.messageSource.getMessage("cryptography.selene.vote_options.map", new Object[] {number}, null));

    for (int i = 0; i < number; i++) {
      final VoteOption voteOption = voteOptions.get(i);

      if (voteOption.getOptionNumberInGroup() == null) {
        final int size = optionNumbersInGroup.size();
        BigInteger optionNumberInGroup = null;

        while (optionNumbersInGroup.size() < (size + 1)) {
          final int optionNumber = this.getRandom().nextInt(Integer.MAX_VALUE - 1) + 1;
          optionNumberInGroup = wrapper.getG().modPow(BigInteger.valueOf(optionNumber), wrapper.getP());

          optionNumbersInGroup.add(optionNumberInGroup);
        }

        voteOption.setOptionNumberInGroup(optionNumberInGroup);
        this.updateProgress(100 * i / (float) number);
      }
    }

    this.endProgress();
  }

  /**
   * Merges the Verificatum teller information files ready to perform key generation, shuffling, mixing or decryption.
   *
   * @param parameters             The election parameters.
   * @param teller                 The number of the teller. Each teller has a unique number, starting at 1.
   * @param tellerInformationFiles The teller information files to be merged.
   * @throws CryptographyException if the teller could not be setup.
   */
  @Override
  public void mergeTeller(final Parameters parameters, final int teller, final File... tellerInformationFiles) throws CryptographyException {
    this.checkTellers(parameters, teller);

    // Merge the teller information files.
    this.startProgress(this.messageSource.getMessage("cryptography.selene.merge.teller", new Object[] {teller, parameters.getNumberOfTellers()}, null));
    this.verificatumHelper.mergeTeller(parameters, teller);
    this.endProgress();
  }

  /**
   * @param parameters     The election parameters.
   * @param keyPair        The election key pair.
   * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
   * @param trackerNumbers The tracker numbers for conversion of tracker number in group to plaintext tracker number.
   * @param voteOptions    The list of vote options for conversion of option number in group to plaintext vote.
   * @param voters         The list of voters with their encrypted votes and encrypted tracker numbers.
   * @return The mixed list of voter data with plaintext vote and tracker number, and the corresponding proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public ProofWrapper<List<Voter>> mixVotes(final Parameters parameters, final KeyPair keyPair, final int teller, final List<TrackerNumber> trackerNumbers,
                                            final List<VoteOption> voteOptions, final List<Voter> voters) throws CryptographyException {
    if (trackerNumbers.size() < voters.size()) {
      throw new CryptographyException("Number of tracker numbers insufficient for voters: " + trackerNumbers.size() + " vs. " + voters.size());
    }

    if (parameters.getNumberOfTellers() > 0) {
      this.checkTellers(parameters, teller);
    }

    try {
      // Extract the encrypted tracker number and vote values as cipher texts.
      final List<List<CipherText>> cipherTexts = voters.stream().map(voter -> {
        try {
          final byte[] encryptedTrackerNumberInGroup = voter.getTrackerNumber().getEncryptedTrackerNumberInGroup();
          final byte[] encryptedVote = voter.getEncryptedVote();

          if ((encryptedTrackerNumberInGroup != null) && (encryptedTrackerNumberInGroup.length > 0) &&
              (encryptedVote != null) && (encryptedVote.length > 0)) {
            return Arrays.asList(new CipherText(encryptedTrackerNumberInGroup), new CipherText(encryptedVote));
          }
          else {
            return null;
          }
        }
        catch (final Exception e) {
          throw new RuntimeException(e); // Re-throw as an unchecked exception because of the lambda.
        }
      }).filter(Objects::nonNull).collect(Collectors.toList());

      // Mix the encrypted votes: shuffle and decrypt.
      this.startProgress(this.messageSource.getMessage("cryptography.selene.mix.votes", new Object[] {voters.size()}, null));
      final List<List<BigInteger>> plainTexts = new ArrayList<>();
      final File proofFile;

      if (parameters.getNumberOfTellers() <= 0) {
        // Local shuffle with an empty proof file. This does not re-encrypt.
        Collections.shuffle(cipherTexts);

        // Now decrypt.
        for (final List<CipherText> cipherText : cipherTexts) {
          final BigInteger trackerNumberInGroup = new BigInteger(1, this.elgamalAlgorithmHelper.decrypt(parameters, keyPair, cipherText.get(0).toByteArray()));
          final BigInteger optionNumberInGroup = new BigInteger(1, this.elgamalAlgorithmHelper.decrypt(parameters, keyPair, cipherText.get(1).toByteArray()));
          plainTexts.add(Arrays.asList(trackerNumberInGroup, optionNumberInGroup));
        }

        try {
          proofFile = Files.createTempFile(null, null).toFile();
        }
        catch (final Exception e) {
          throw new CryptographyException("Could not create empty proof file", e);
        }
      }
      else {
        // Verificatum mix with proof file. Here Verificatum requires a single list of interleaved ciphertexts.
        final List<CipherText> flatCipherTexts = cipherTexts.stream().flatMap(Collection::stream).collect(Collectors.toList());
        final ProofWrapper<List<BigInteger>> mix = this.verificatumHelper.mix(parameters, teller, 2, flatCipherTexts); // Tracker number and vote together.

        for (int i = 0; i < mix.getObject().size(); i += 2) {
          plainTexts.add(Arrays.asList(mix.getObject().get(i), mix.getObject().get(i + 1)));
        }

        proofFile = mix.getProofFile();
      }

      // Extract the mixed values and convert them back into voter objects.
      final List<Voter> mixedVoters = new ArrayList<>();

      for (final List<BigInteger> plainText : plainTexts) {
        final Voter voter = new Voter();

        // Look up the tracker number
        final TrackerNumber trackerNumber = trackerNumbers.stream()
            .filter(tracker -> tracker.getTrackerNumberInGroup().equals(plainText.get(0)))
            .findAny().orElse(null);

        if (trackerNumber == null) {
          throw new CryptographyException("Could not find tracker number for tracker number in group " + plainText.get(0));
        }

        voter.setTrackerNumber(trackerNumber);

        // Lookup the plain text vote.
        final VoteOption voteOption = voteOptions.stream()
            .filter(option -> option.getOptionNumberInGroup().equals(plainText.get(1)))
            .findAny().orElse(null);

        if (voteOption == null) {
          throw new CryptographyException("Could not find vote option for vote option in group " + plainText.get(1));
        }

        voter.setPlainTextVote(voteOption.getOption());
        mixedVoters.add(voter);
      }

      this.endProgress();

      return new ProofWrapper<>(mixedVoters, proofFile);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not mix votes", e);
    }
  }

  /**
   * Shuffles the tracker numbers.
   *
   * @param parameters     The election parameters.
   * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
   * @param trackerNumbers The tracker numbers to shuffle
   * @return The shuffled tracker numbers and the corresponding shuffle proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  @Override
  public ProofWrapper<List<TrackerNumber>> shuffleTrackerNumbers(final Parameters parameters, final int teller, final List<TrackerNumber> trackerNumbers) throws CryptographyException {
    if (parameters.getNumberOfTellers() > 0) {
      this.checkTellers(parameters, teller);
    }

    try {
      // Extract the encrypted tracker number values so that the linkage between the encrypted plaintext values is obscured because of re-encryption.
      final List<CipherText> cipherTexts = trackerNumbers.stream().map(trackerNumber -> {
        try {
          return new CipherText(trackerNumber.getEncryptedTrackerNumberInGroup());
        }
        catch (final Exception e) {
          throw new RuntimeException(e); // Re-throw as an unchecked exception because of the lambda.
        }
      }).collect(Collectors.toList());

      // Shuffle the tracker numbers.
      this.startProgress(this.messageSource.getMessage("cryptography.selene.shuffle.tracker_numbers", new Object[] {trackerNumbers.size()}, null));
      final List<CipherText> shuffledCipherTexts;
      final List<TrackerNumber> shuffledTrackerNumbers;
      final File proofFile;

      if (parameters.getNumberOfTellers() <= 0) {
        // Local shuffle with an empty proof file. This does not re-encrypt.
        Collections.shuffle(cipherTexts);
        shuffledCipherTexts = cipherTexts;

        try {
          proofFile = Files.createTempFile(null, null).toFile();
        }
        catch (final Exception e) {
          throw new CryptographyException("Could not create empty proof file", e);
        }
      }
      else {
        // Verificatum shuffle with proof file.
        final ProofWrapper<List<CipherText>> shuffle = this.verificatumHelper.shuffle(parameters, teller, 1, cipherTexts);
        shuffledCipherTexts = shuffle.getObject();
        proofFile = shuffle.getProofFile();
      }

      // Extract the shuffled encrypted values.
      shuffledTrackerNumbers = shuffledCipherTexts.stream().map(i -> {
        try {
          return new TrackerNumber(null, null, i.toByteArray());
        }
        catch (CryptographyException e) {
          throw new RuntimeException(e); // Re-throw as an unchecked exception because of the lambda.
        }
      }).collect(Collectors.toList());

      this.endProgress();

      return new ProofWrapper<>(shuffledTrackerNumbers, proofFile);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not shuffle tracker numbers", e);
    }
  }

  /**
   * Verifies the non-interactive zero-knowledge proofs of knowledge of a commitment for a voter.
   *
   * @param parameters      The election parameters.
   * @param keyPair         The election key pair.
   * @param voterPublicKey  The voter's public encryption key.
   * @param commitment      The voter's commitment.
   * @param commitmentProof The proof of knowledge of the voter's commitment.
   * @return True if the proof is valid.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  private boolean verifyCommitmentProof(final Parameters parameters, final KeyPair keyPair, final BigInteger voterPublicKey, final Commitment commitment,
                                        final CommitmentProof commitmentProof) throws CryptographyException {
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();
    final BigInteger g = wrapper.getG();

    // Form the statements.
    final CipherText cipherTextG = new CipherText(commitment.getEncryptedG()); // (A1, A2).
    final CipherText cipherTextH = new CipherText(commitment.getEncryptedH()); // (B1, B2).

    // pi11 =? NIZK2.Verify(A1; g; s1) where s1 is the encryptionSecretG.
    boolean result = this.schnorrAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi11(), new Statement(cipherTextG.getAlpha(), g));

    // pi12 =? NIZK2.Verify(B1; g; s2) where s2 is the encryptionSecretH.
    result &= this.schnorrAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi12(), new Statement(cipherTextH.getAlpha(), g));

    // pi21 =? NIZK1.Verify(A1Dash, A1; A2Dash, A2; t).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi21(), new Statement(commitmentProof.getA1Dash(),
        cipherTextG.getAlpha()), new Statement(commitmentProof.getA2Dash(), cipherTextG.getBeta()));

    // pi22 =? NIZK1.Verify(B1Dash, B1; B2Dash, B2; t).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi22(), new Statement(commitmentProof.getB1Dash(),
        cipherTextH.getAlpha()), new Statement(commitmentProof.getB2Dash(), cipherTextH.getBeta()));

    // pi23 =? NIZK1.Verify(B1Dash, B1; B2Dash, B2; t).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi23(), new Statement(commitmentProof.getA1Dash(),
        cipherTextG.getAlpha()), new Statement(commitmentProof.getB1Dash(), cipherTextH.getAlpha()));

    // pi31 =? NIZK1.Verify(A1Dash, g; A2Dash * C^-1 mod p, electionPublicKey).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi31(), new Statement(commitmentProof.getA1Dash(), g),
        new Statement(commitmentProof.getA2Dash().multiply(commitmentProof.getC().modPow(BigInteger.ONE.negate(), p)).mod(p), keyPair.getPublicKey()));

    // pi32 =? NIZK1.Verify(B1Dash, g; B2Dash * D^-1 mod p, electionPublicKey).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi32(), new Statement(commitmentProof.getB1Dash(), g),
        new Statement(commitmentProof.getB2Dash().multiply(commitmentProof.getD().modPow(BigInteger.ONE.negate(), p)).mod(p), keyPair.getPublicKey()));

    // pi4 =? NIZK1.Verify(C, g; D, voterPublicKey).
    result &= this.chaumPedersenAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi4(), new Statement(commitmentProof.getC(), g),
        new Statement(commitmentProof.getD(), voterPublicKey));

    // pi5 =? NIZK2.Verify(C, g).
    result &= this.schnorrAlgorithmHelper.verifyProof(parameters, commitmentProof.getPi5(), new Statement(commitmentProof.getC(), g));

    return result;
  }

  /**
   * Verifies the non-interactive zero-knowledge proofs of knowledge of an ElGamal encryption.
   *
   * @param parameters       The election parameters.
   * @param keyPair          The election key pair.
   * @param encrypted        The encrypted value.
   * @param signatureKeyPair The voter's signing key pair used for the encrypted vote signature.
   * @param encryptProof     The proof of encryption.
   * @return True if the proof is valid.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  boolean verifyEncryptProof(final Parameters parameters, final KeyPair keyPair, final byte[] encrypted, final KeyPair signatureKeyPair,
                             final EncryptProof encryptProof) throws CryptographyException {
    final DHParametersWrapper wrapper = (DHParametersWrapper) parameters;
    final BigInteger p = wrapper.getP();
    final BigInteger q = wrapper.getQ();

    // Extract the ciphertext values.
    final CipherText cipherText = new CipherText(encrypted); // (c1, c2).

    // Form the hash c = H(c1, c2, cR1, cR2, vk, p, q).
    final BigInteger c = this.hash(q.bitLength(), cipherText.getAlpha(), cipherText.getBeta(), encryptProof.getC1R(), encryptProof.getC2R(),
        signatureKeyPair.getPublicKey(), p, q);

    // Verify c1Bar =? c1^c * cR1.
    final BigInteger c1Bar = cipherText.getAlpha().modPow(c, p).multiply(encryptProof.getC1R()).mod(p);
    boolean result = encryptProof.getC1Bar().equals(c1Bar);

    // Verify c2Bar =? c2^c * cR2.
    final BigInteger c2Bar = cipherText.getBeta().modPow(c, p).multiply(encryptProof.getC2R()).mod(p);
    result &= encryptProof.getC2Bar().equals(c2Bar);

    // Verify s =? sign(encrypted)
    result &= this.dsaAlgorithmHelper.verify(parameters, signatureKeyPair, encrypted, encryptProof.getEncryptedVoteSignature());

    return result;
  }

  /**
   * Writes the content as CSV to a file using the optional view. If an optional view is provided then only those properties with a view that matches are written.
   * No properties are included by default if they do not have an associated {@link JsonView}.
   *
   * @param clazz   The class (or contained class) of the content.
   * @param content The content to write.
   * @param view    The optional view to filter for.
   * @return The CSV file.
   * @throws CryptographyException if the file could not be written.
   */
  private File writeCSVToFile(final Class<?> clazz, final Object content, final Class<?> view) throws CryptographyException {
    final File csvFile;

    try {
      // Use a shell component to write the CSV file.
      csvFile = Files.createTempFile(null, null).toFile();
      final BaseShellComponent shellComponent = new BaseShellComponent() {
      };
      shellComponent.writeCSV(csvFile, clazz, content, view);
    }
    catch (final Exception e) {
      throw new CryptographyException("Could not create CSV file", e);
    }

    return csvFile;
  }
}
