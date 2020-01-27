/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;

/**
 * Implements a {@link CryptographyHelper.ProgressListener} for the shell.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ShellProgress implements CryptographyHelper.ProgressListener {

  /** The minimum change in progress that can be reported. */
  private static final int MINIMUM_CHANGE = 5;

  /** The last progress reported. */
  private int lastProgress = 0;

  /** The start time. */
  private long start = 0;

  /**
   * Called when an operation ends.
   */
  @Override
  public void onEnd() {
    this.lastProgress = 100;
    System.out.println(String.format("%d%% (%.3fs)", this.lastProgress, (System.currentTimeMillis() - this.start) / 1000f));
  }

  /**
   * Called when progress has been made.
   *
   * @param progress The percentage progress.
   */
  @Override
  public void onProgress(final float progress) {
    final int rounded = Math.round(progress);

    if ((this.lastProgress < rounded) && (rounded < 100) && ((rounded - this.lastProgress) >= MINIMUM_CHANGE)) {
      this.lastProgress = rounded;
      System.out.print(String.format("%d%%..", this.lastProgress));
      System.out.flush();
    }
  }

  /**
   * Called when an operation starts.
   *
   * @param name The name of the progress item.
   */
  @Override
  public void onStart(final String name) {
    this.start = System.currentTimeMillis();
    this.lastProgress = 0;
    System.out.print(String.format("%s: %d%%..", name, this.lastProgress));
  }
}
