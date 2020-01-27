/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.test.util.ReflectionTestUtils;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.io.File;
import java.math.BigInteger;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Java cryptography helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class JavaCryptographyHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testGetRandom() {
    final CryptographyHelper helper = new TestJavaCryptographyHelper();
    assertThat(helper).isNotNull();
    assertThat(helper.getRandom()).isNotNull();

    final int length = 32;
    final byte[] random = helper.getRandomBytes(length);
    assertThat(random).isNotNull();
    assertThat(random.length).isEqualTo(length);

    int zeros = 0;

    for (final byte randomByte : random) {
      zeros += randomByte == 0 ? 1 : 0;
    }

    assertThat(zeros).isNotEqualTo(length);
  }

  @Test
  public void testIsUnlimitedStrength() {
    final CryptographyHelper helper = new TestJavaCryptographyHelper();
    assertThat(helper).isNotNull();
    assertThat(helper.isUnlimitedStrength()).isNotNull();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testProgress() {
    final TestJavaCryptographyHelper helper = new TestJavaCryptographyHelper();
    assertThat(helper).isNotNull();

    final Set<CryptographyHelper.ProgressListener> listeners = (Set<CryptographyHelper.ProgressListener>) ReflectionTestUtils.getField(helper, "progressListeners");
    assertThat(listeners).isNotNull();
    assertThat(listeners).isEmpty();

    final TestProgress listener = new TestProgress();
    helper.addProgressListener(listener);

    assertThat(listeners).isNotEmpty();
    assertThat(listeners.toArray()[0]).isEqualTo(listener);

    assertThat(listener.started).isFalse();
    assertThat(listener.progress).isEqualTo(0);
    assertThat(listener.ended).isFalse();

    helper.startProgress("name");
    assertThat(listener.started).isTrue();
    assertThat(listener.progress).isEqualTo(0);
    assertThat(listener.ended).isFalse();

    helper.updateProgress(23f);
    assertThat(listener.started).isTrue();
    assertThat(listener.progress).isEqualTo(23f);
    assertThat(listener.ended).isFalse();

    helper.endProgress();
    assertThat(listener.started).isTrue();
    assertThat(listener.progress).isEqualTo(23f);
    assertThat(listener.ended).isTrue();

    helper.removeProgressListener(listener);
    assertThat(listeners).isEmpty();
  }

  /**
   * Java cryptography helper implementation.
   */
  public static class TestJavaCryptographyHelper extends JavaCryptographyHelper {

    @Override
    public void associateVoters(final List<Voter> source, final List<Voter> destination) throws CryptographyException {

    }

    @Override
    public void completeCommitments(final Parameters parameters, final List<Voter> voters, final List<List<Commitment>> commitments) throws CryptographyException {

    }

    @Override
    public ProofWrapper<List<Commitment>> createCommitments(final Parameters parameters, final KeyPair keyPair, final List<VoterKeyPairs> votersKeyPairs,
                                                            final List<TrackerNumber> trackerNumbers) throws CryptographyException {
      return null;
    }

    @Override
    public KeyPair createElectionKeyPair(final Parameters parameters, final Object... options) throws CryptographyException {
      return null;
    }

    @Override
    public Parameters createElectionParameters(final Object... options) {
      return null;
    }

    @Override
    public File createTeller(final Parameters parameters, final int teller, final String ip, final int tellerPort, final int hintPort) throws CryptographyException {
      return null;
    }

    @Override
    public Set<TrackerNumber> createTrackerNumbers(final Parameters parameters, final KeyPair keyPair, final int number) throws CryptographyException {
      return null;
    }

    @Override
    public List<VoterKeyPairs> createVotersKeyPairs(final int voters, final Parameters parameters) {
      return null;
    }

    @Override
    public ProofWrapper<List<Voter>> decryptCommitments(final Parameters parameters, final KeyPair keyPair, final int teller,
                                                        final List<VoterKeyPairs> votersKeyPairs,
                                                        final List<TrackerNumber> trackerNumbers, final List<List<Commitment>> commitments) throws CryptographyException {
      return null;
    }

    @Override
    public TrackerNumber decryptTrackerNumber(final Parameters parameters, final BigInteger alpha, final BigInteger beta, final BigInteger publicKey,
                                              final List<VoterKeyPairs> votersKeyPairs, final List<TrackerNumber> trackerNumbers) throws CryptographyException {
      return null;
    }

    @Override
    public ProofWrapper<List<Voter>> encryptVotes(final Parameters parameters, final KeyPair keyPair, final List<VoterKeyPairs> votersKeyPairs,
                                                  final List<VoteOption> voteOptions, final List<Voter> voters, final List<EncryptProof> ersEncryptProofs) throws CryptographyException {
      return null;
    }

    @Override
    public Class<? extends Parameters> getElectionParametersClass() {
      return null;
    }

    @Override
    public File[] getTellerInformationFiles(final Parameters parameters, final int teller) throws CryptographyException {
      return new File[0];
    }

    @Override
    public void mapVoteOptions(final Parameters parameters, final List<VoteOption> voteOptions) throws CryptographyException {

    }

    @Override
    public void mergeTeller(final Parameters parameters, final int teller, final File... tellerInformationFiles) throws CryptographyException {

    }

    @Override
    public ProofWrapper<List<Voter>> mixVotes(final Parameters parameters, final KeyPair keyPair, final int teller, final List<TrackerNumber> trackerNumbers,
                                              final List<VoteOption> voteOptions, final List<Voter> voters) throws CryptographyException {
      return null;
    }

    @Override
    public ProofWrapper<List<TrackerNumber>> shuffleTrackerNumbers(final Parameters parameters, final int teller, final List<TrackerNumber> trackerNumbers) throws CryptographyException {
      return null;
    }
  }

  /**
   * Progress implementation.
   */
  public static class TestProgress implements CryptographyHelper.ProgressListener {

    boolean ended = false;

    float progress = 0f;

    boolean started = false;

    @Override
    public void onEnd() {
      this.ended = true;
    }

    @Override
    public void onProgress(final float progress) {
      this.progress = progress;
    }

    @Override
    public void onStart(final String name) {
      this.started = true;
    }
  }
}
