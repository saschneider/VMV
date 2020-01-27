/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.io.File;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.Set;

/**
 * Interface defining the available cryptographic functions.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public interface CryptographyHelper {

  /** Default Verificatum hint port. */
  int DEFAULT_HINT_PORT = 8081;

  /** Default number of tellers. */
  int DEFAULT_NUMBER_OF_TELLERS = 4;

  /** Default IP address: signifies that the locally registered IP address should be used. */
  String DEFAULT_TELLER_IP = "<local>"; // String so that it can be used in an annotation.

  /** Default Verificatum teller port. */
  int DEFAULT_TELLER_PORT = 8080;

  /** Default threshold tellers. */
  int DEFAULT_THRESHOLD_TELLERS = 3;

  /**
   * Adds a progress listener which will receive progress feedback. If the listener has already been added, it will be ignored.
   *
   * @param listener The listener to add.
   */
  void addProgressListener(ProgressListener listener);

  /**
   * Associates the voter identifier in the source list with the voter parameters in the destination list. The destionation list objects are updated.
   *
   * @param source      The source voter list.
   * @param destination The destination voter list.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  void associateVoters(List<Voter> source, List<Voter> destination) throws CryptographyException;

  /**
   * Completes the formation of the commitments after the voting period has finished and updates the voter information with the remaining commitment values.
   *
   * @param parameters  The election parameters.
   * @param voters      The list of voters with their partial commitment values.
   * @param commitments The private commitment data from each teller.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  void completeCommitments(Parameters parameters, List<Voter> voters, List<List<Commitment>> commitments) throws CryptographyException;

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
  ProofWrapper<List<Commitment>> createCommitments(Parameters parameters, KeyPair keyPair, List<VoterKeyPairs> votersKeyPairs,
                                                   List<TrackerNumber> trackerNumbers) throws CryptographyException;

  /**
   * Creates the election key pair using the created parameters.
   *
   * @param parameters Key generation parameters.
   * @param options    Key parameter options.
   * @return The created key pair.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  KeyPair createElectionKeyPair(Parameters parameters, Object... options) throws CryptographyException;

  /**
   * Creates the election parameters using the required options.
   *
   * @param options Key parameter options.
   * @return The created parameters.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  Parameters createElectionParameters(Object... options) throws CryptographyException;

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
  File createTeller(Parameters parameters, int teller, String ip, int tellerPort, int hintPort) throws CryptographyException;

  /**
   * Creates the required tracker numbers. Tracker numbers are guaranteed to be positive and unique.
   *
   * @param parameters The election parameters.
   * @param keyPair    The election key pair.
   * @param number     The number to create.
   * @return The set of tracker numbers.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  Set<TrackerNumber> createTrackerNumbers(Parameters parameters, KeyPair keyPair, int number) throws CryptographyException;

  /**
   * Creates key pairs for all voters using the required election parameters.
   *
   * @param voters     The number of voters.
   * @param parameters Key generation parameters.
   * @return A created key pairs per voter.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  List<VoterKeyPairs> createVotersKeyPairs(int voters, Parameters parameters) throws CryptographyException;

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
  ProofWrapper<List<Voter>> decryptCommitments(Parameters parameters, KeyPair keyPair, int teller, List<VoterKeyPairs> votersKeyPairs,
                                               List<TrackerNumber> trackerNumbers, List<List<Commitment>> commitments) throws CryptographyException;

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
  TrackerNumber decryptTrackerNumber(Parameters parameters, BigInteger alpha, BigInteger beta, BigInteger publicKey, List<VoterKeyPairs> votersKeyPairs,
                                     List<TrackerNumber> trackerNumbers) throws CryptographyException;

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
  ProofWrapper<List<Voter>> encryptVotes(Parameters parameters, KeyPair keyPair, List<VoterKeyPairs> votersKeyPairs, List<VoteOption> voteOptions,
                                         List<Voter> voters, final List<EncryptProof> ersEncryptProofs) throws CryptographyException;

  /**
   * @return The class used for the election parameters.
   */
  Class<? extends Parameters> getElectionParametersClass();

  /**
   * @return The secure random number generator.
   */
  SecureRandom getRandom();

  /**
   * Obtain cryptographically strong bytes of the specified length.
   *
   * @param length The number of required random bytes.
   * @return The random bytes.
   */
  byte[] getRandomBytes(int length);

  /**
   * Gets the array of local teller information files in order for all tellers. The files are assumed to be held within the specified teller directory.
   *
   * @param parameters The election parameters.
   * @param teller     The number of the teller. Each teller has a unique number, starting at 1.
   * @return The array of local teller information files.
   * @throws CryptographyException if incorrect teller information is provided.
   */
  File[] getTellerInformationFiles(Parameters parameters, int teller) throws CryptographyException;

  /**
   * Determines if the Java JCE unlimited strength cryptography policy files are installed so that larger key lengths can be used.
   *
   * If unlimited strength is not available, please download and install the correct JAR files for the Java version. For Java 1.8:
   * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
   *
   * @return True if the unlimited strength policy files are installed.
   */
  boolean isUnlimitedStrength();

  /**
   * Maps the list of vote options to numbers in the election parameter group. The list of vote options is modified to contain the mapping.
   *
   * @param parameters  The election parameters.
   * @param voteOptions The vote options to map.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  void mapVoteOptions(Parameters parameters, List<VoteOption> voteOptions) throws CryptographyException;

  /**
   * Merges the Verificatum teller information files ready to perform key generation, shuffling, mixing or decryption.
   *
   * @param parameters             The election parameters.
   * @param teller                 The number of the teller. Each teller has a unique number, starting at 1.
   * @param tellerInformationFiles The teller information files to be merged.
   * @throws CryptographyException if the teller could not be setup.
   */
  void mergeTeller(Parameters parameters, int teller, File... tellerInformationFiles) throws CryptographyException;

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
  ProofWrapper<List<Voter>> mixVotes(Parameters parameters, KeyPair keyPair, int teller, List<TrackerNumber> trackerNumbers, List<VoteOption> voteOptions,
                                     List<Voter> voters) throws CryptographyException;

  /**
   * Removes a progress listener. If the listener was not added, it will be ignored.
   *
   * @param listener The listener to remove.
   */
  void removeProgressListener(ProgressListener listener);

  /**
   * Shuffles the tracker numbers.
   *
   * @param parameters     The election parameters.
   * @param teller         The number of the teller. Each teller has a unique number, starting at 1.
   * @param trackerNumbers The tracker numbers to shuffle
   * @return The shuffled tracker numbers and the corresponding shuffle proof file. The proof file may be deleted once used.
   * @throws CryptographyException if the cryptographic operation could not be completed.
   */
  ProofWrapper<List<TrackerNumber>> shuffleTrackerNumbers(Parameters parameters, int teller, List<TrackerNumber> trackerNumbers) throws CryptographyException;

  /**
   * Used to provide progress on operations.
   */
  interface ProgressListener {

    /**
     * Called when an operation ends.
     */
    void onEnd();

    /**
     * Called when progress has been made.
     *
     * @param progress The percentage progress.
     */
    void onProgress(final float progress);

    /**
     * Called when an operation starts.
     *
     * @param name The name of the progress item.
     */
    void onStart(final String name);
  }
}
