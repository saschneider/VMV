/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.SecureRandom;
import java.security.Security;
import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Java partial implementation of the {@link CryptographyHelper}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public abstract class JavaCryptographyHelper extends BaseHelper implements CryptographyHelper {

  /** AES algorithm. */
  private static final String AES = "AES";

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(JavaCryptographyHelper.class);

  /** The set of progress listeners. */
  private final Set<ProgressListener> progressListeners = new LinkedHashSet<>();

  /** Cryptographically strong random number generator. */
  private final SecureRandom random;

  /**
   * Default constructor. Initialises Bouncy Castle and other cryptographic primitives.
   */
  JavaCryptographyHelper() {
    // Install Bouncy Castle.
    Security.addProvider(new BouncyCastleProvider());

    // Initialise the random number generator. This uses Javas's default implementation which will correspondingly use /dev/random.
    this.random = new SecureRandom();
  }

  /**
   * Adds a progress listener which will receive progress feedback. If the listener has already been added, it will be ignored.
   *
   * @param listener The listener to add.
   */
  public void addProgressListener(final ProgressListener listener) {
    this.progressListeners.add(listener);
  }

  /**
   * Called to end progress for all listeners.
   */
  void endProgress() {
    for (final ProgressListener listener : this.progressListeners) {
      listener.onEnd();
    }
  }

  /**
   * @return The secure random number generator.
   */
  @Override
  public SecureRandom getRandom() {
    return this.random;
  }

  /**
   * Obtain cryptographically strong bytes of the specified length.
   *
   * @param length The number of required random bytes.
   * @return The random bytes.
   */
  @Override
  public byte[] getRandomBytes(final int length) {
    final byte[] bytes = new byte[length];
    this.random.nextBytes(bytes);
    return bytes;
  }

  /**
   * Determines if the Java JCE unlimited strength cryptography policy files are installed so that larger key lengths can be used.
   *
   * If unlimited strength is not available, please download and install the correct JAR files for the Java version. For Java 1.8:
   * http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html
   *
   * @return True if the unlimited strength policy files are installed.
   */
  @Override
  public boolean isUnlimitedStrength() {
    boolean result = false;

    // Modified from https://gist.github.com/evaryont/6786915.
    try {
      // Get the maximum allowed key length for AES.
      final int maxKeyLength = Cipher.getMaxAllowedKeyLength(AES);

      // The unlimited policy is included if
      result = maxKeyLength >= Integer.MAX_VALUE;
    }
    catch (final Exception e) {
      LOG.error("Could not check if unlimited strength is installed", e);
    }

    return result;
  }

  /**
   * Removes a progress listener. If the listener was not added, it will be ignored.
   *
   * @param listener The listener to remove.
   */
  public void removeProgressListener(final ProgressListener listener) {
    this.progressListeners.remove(listener);
  }

  /**
   * Called to start progress for all listeners.
   *
   * @param name The name of the progress item.
   */
  void startProgress(final String name) {
    for (final ProgressListener listener : this.progressListeners) {
      listener.onStart(name);
    }
  }

  /**
   * Called to update progress for all listeners.
   *
   * @param progress The percentage progress.
   */
  void updateProgress(final float progress) {
    for (final ProgressListener listener : this.progressListeners) {
      listener.onProgress(progress);
    }
  }
}
