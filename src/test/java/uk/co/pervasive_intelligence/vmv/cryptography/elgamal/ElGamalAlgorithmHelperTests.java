/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.elgamal;

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
 * ElGamal algorithm helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ElGamalAlgorithmHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testCreateKeysParameters() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Parameters parameters = helper.createParameters(new SecureRandom(), 256, 128);
    assertThat(parameters).isNotNull();

    final DHParametersWrapper elgamalParametersWrapper = (DHParametersWrapper) parameters;

    final BigInteger[] divide = elgamalParametersWrapper.getP().subtract(BigInteger.ONE).divideAndRemainder(elgamalParametersWrapper.getQ());
    assertThat(divide[0]).isEqualTo(BigInteger.valueOf(2));
    assertThat(divide[1]).isEqualTo(BigInteger.ZERO);

    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);
    assertThat(keyPair).isNotNull();
    assertThat(keyPair.getPrivateKey()).isNotNull();
    assertThat(keyPair.getPublicKey()).isNotNull();
  }

  @Test
  public void testDecryptMissingKey() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair originalKeyPair = helper.createKeys(new SecureRandom(), parameters);
    final KeyPair keyPair = new NoPrivateKeyPair(originalKeyPair);

    final BigInteger numberInGroup = parameters.getG().modPow(BigInteger.valueOf(11), parameters.getP());
    final byte[] data = numberInGroup.toByteArray();

    this.exception.expect(CryptographyException.class);
    helper.decrypt(parameters, keyPair, data);
  }

  @Test
  public void testEncryptDecrypt() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final BigInteger numberInGroup = parameters.getG().modPow(BigInteger.valueOf(11), parameters.getP());
    final byte[] data = numberInGroup.toByteArray();

    final byte[][] encrypted = helper.encrypt(new SecureRandom(), parameters, keyPair, data);
    assertThat(encrypted).isNotNull();

    final byte[] decrypted = helper.decrypt(parameters, keyPair, encrypted[0]);
    assertThat(decrypted).isNotNull();
    assertThat(decrypted).isEqualTo(data);

    final byte[][] encryptedAgain = helper.encrypt(new SecureRandom(), parameters, keyPair, data);
    assertThat(encryptedAgain).isNotNull();
    assertThat(encryptedAgain[0]).isNotEqualTo(encrypted[0]);
  }

  @Test
  public void testEncryptMissingKey() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair originalKeyPair = helper.createKeys(new SecureRandom(), parameters);
    final KeyPair keyPair = new NoPublicKeyPair(originalKeyPair);

    final BigInteger numberInGroup = parameters.getG().modPow(BigInteger.valueOf(11), parameters.getP());
    final byte[] data = numberInGroup.toByteArray();

    this.exception.expect(CryptographyException.class);
    helper.encrypt(new SecureRandom(), parameters, keyPair, data);
  }

  @Test
  public void testGenerateProof() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);

    final BigInteger witness = BigInteger.ONE;
    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);

    this.exception.expect(CryptographyException.class);
    helper.generateProof(new SecureRandom(), parameters, witness, statement);
  }

  @Test
  public void testSign() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final BigInteger numberInGroup = parameters.getG().modPow(BigInteger.valueOf(11), parameters.getP());
    final byte[] data = numberInGroup.toByteArray();

    this.exception.expect(CryptographyException.class);
    helper.sign(parameters, keyPair, data);
  }

  @Test
  public void testVerify() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);
    final KeyPair keyPair = helper.createKeys(new SecureRandom(), parameters);

    final BigInteger numberInGroup = parameters.getG().modPow(BigInteger.valueOf(11), parameters.getP());
    final byte[] data = numberInGroup.toByteArray();
    final byte[] signature = new byte[] {4, 3, 2, 1};

    this.exception.expect(CryptographyException.class);
    helper.verify(parameters, keyPair, data, signature);
  }

  @Test
  public void testVerifyProof() throws Exception {
    final ElGamalAlgorithmHelper helper = new ElGamalAlgorithmHelper();
    assertThat(helper).isNotNull();

    final DHParametersWrapper parameters = (DHParametersWrapper) helper.createParameters(new SecureRandom(), 256, 128);

    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);
    final Proof proof = new Proof();

    this.exception.expect(CryptographyException.class);
    helper.verifyProof(parameters, proof, statement);
  }
}
