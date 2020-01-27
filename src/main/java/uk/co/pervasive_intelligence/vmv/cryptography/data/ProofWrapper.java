/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import java.io.File;

/**
 * Wraps an object with the corresponding proof file.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ProofWrapper<T> {

  /** The object for which the proof file is provided. */
  private final T object;

  /** The proof file. */
  private final File proofFile;

  /**
   * Constructor which allows the proof file to be associated with the object being wrapped.
   *
   * @param object    The object for which the proof file is provided.
   * @param proofFile The proof file.
   */
  public ProofWrapper(final T object, final File proofFile) {
    this.object = object;
    this.proofFile = proofFile;
  }

  /**
   * @return The object for which the proof file is provided.
   */
  public T getObject() {
    return this.object;
  }

  /**
   * @return The proof file.
   */
  public File getProofFile() {
    return this.proofFile;
  }
}
