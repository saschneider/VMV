/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import com.fasterxml.jackson.annotation.JsonView;

/**
 * Defines the views used by Jackson to filter fields using {@link JsonView}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class JacksonViews {

  /*
   * This property is explicitly included in an ERS export of data.
   */
  public static class ERSExport extends Public {

  }

  /*
   * This property is explicitly included in an ERS import of data.
   */
  public static class ERSImport {

  }

  /*
   * This property is explicitly included in an ERS import of data with public keys.
   */
  public static class ERSKeyImport {

  }

  /*
   * This property is explicitly included in an ERS import of data with optional plaintext or encrypted votes.
   */
  public static class ERSVoteEncryptedImport {

  }

  /*
   * This property is explicitly included in an ERS export of data with encrypted vote.
   */
  public static class ERSVoteExport {

  }

  /*
   * This property is explicitly included in an ERS import of data with plaintext vote.
   */
  public static class ERSVoteImport {

  }

  /**
   * Public when mixed.
   */
  public static class Mixed {

  }

  /**
   * Include this field only in private data.
   */
  public static class Private {

  }

  /**
   * Include this property publicly.
   */
  public static class Public {

  }

  /**
   * Include this property publicly, but only for restricted stages.
   */
  public static class RestrictedPublic extends Public {

  }

  /**
   * Include this property in vote publication data.
   */
  public static class Vote {

  }

  /**
   * Include this property in vote publication data for a voter.
   */
  public static class VoterVote {

  }
}
