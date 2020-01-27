/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;

/**
 * Base test case class. Contains classes which are used as stubs within descending test classes.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class BaseTestCase {

  /**
   * Key pair where the private key is null.
   */
  public static class NoPrivateKeyPair extends KeyPair {

    public NoPrivateKeyPair(final KeyPair keyPair) {
      super(null, keyPair.getPublicKey());
    }
  }

  /**
   * Key pair where the public key is null.
   */
  public static class NoPublicKeyPair extends KeyPair {

    public NoPublicKeyPair(final KeyPair keyPair) {
      super(keyPair.getPrivateKey(), null);
    }
  }
}
