/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.dsa;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.data.*;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * DSA algorithm helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class DSAAlgorithmHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testCreateKeysNoParameters() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.createKeys(new SecureRandom(), null);
  }

  @Test
  public void testCreateKeysParameters() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    assertThat(parameters).isNotNull();

    final DHParametersWrapper DHParametersWrapper = (DHParametersWrapper) parameters;

    final BigInteger[] divide = DHParametersWrapper.getP().subtract(BigInteger.ONE).divideAndRemainder(DHParametersWrapper.getQ());
    assertThat(divide[1]).isEqualTo(BigInteger.ZERO);

    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPrivateKey()).isNotNull();
    assertThat(keyPair.getPublicKey()).isNotNull();
  }

  @Test
  public void testCreateParametersValues() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Object parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    assertThat(parameters).isNotNull();
  }

  @Test
  public void testDecrypt() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final byte[] data = new byte[] {1, 2, 3, 4};

    this.exception.expect(CryptographyException.class);
    helper.decrypt(parameters, keyPair, data);
  }

  @Test
  public void testEncrypt() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final byte[] data = new byte[] {1, 2, 3, 4};

    this.exception.expect(CryptographyException.class);
    helper.encrypt(new SecureRandom(), parameters, keyPair, data);
  }

  @Test
  public void testGenerateProof() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);

    final BigInteger witness = BigInteger.ONE;
    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);

    this.exception.expect(CryptographyException.class);
    helper.generateProof(new SecureRandom(), parameters, witness, statement);
  }

  @Test
  public void testSignMissingKey() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    final KeyPair originalKeyPair = helper.createKeys(new SecureRandom(), parameters);
    final KeyPair keyPair = new NoPrivateKeyPair(originalKeyPair);

    final byte[] data = new byte[] {1, 2, 3, 4};

    this.exception.expect(CryptographyException.class);
    helper.sign(parameters, keyPair, data);
  }

  @Test
  public void testSignVerify() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final byte[] data = new byte[] {1, 2, 3, 4};
    final byte[] signature = helper.sign(parameters, keyPair, data);
    assertThat(signature).isNotNull();

    assertThat(helper.verify(parameters, keyPair, data, signature)).isTrue();

    final byte[] differentSignature = helper.sign(parameters, keyPair, data);
    assertThat(differentSignature).isNotNull();
    assertThat(differentSignature).isNotEqualTo(signature);

    final byte[] differentData = new byte[] {4, 3, 2, 1};
    assertThat(helper.verify(parameters, keyPair, differentData, signature)).isFalse();
  }

  @Test
  public void testVerifyMissingKey() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);
    final KeyPair originalKeyPair = helper.createKeys(new SecureRandom(), parameters);
    final KeyPair keyPair = new NoPublicKeyPair(originalKeyPair);

    final byte[] data = new byte[] {1, 2, 3, 4};
    final byte[] signature = helper.sign(parameters, keyPair, data);
    assertThat(signature).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.verify(parameters, keyPair, data, signature);
  }

  @Test
  public void testVerifyProof() throws Exception {
    final DSAAlgorithmHelper helper = new DSAAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 1024, 160, 128);

    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);
    final Proof proof = new Proof();

    this.exception.expect(CryptographyException.class);
    helper.verifyProof(parameters, proof, statement);
  }
}
