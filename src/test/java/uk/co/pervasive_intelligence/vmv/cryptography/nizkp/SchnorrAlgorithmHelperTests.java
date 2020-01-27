/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography.nizkp;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyException;
import uk.co.pervasive_intelligence.vmv.cryptography.data.DHParametersWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Proof;
import uk.co.pervasive_intelligence.vmv.cryptography.data.Statement;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Schnorr algorithm helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class SchnorrAlgorithmHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private DHParametersWrapper parameters = null;

  @Before
  public void setUp() throws Exception {
    final ElGamalAlgorithmHelper elGamalAlgorithmHelper = new ElGamalAlgorithmHelper();
    this.parameters = (DHParametersWrapper) elGamalAlgorithmHelper.createParameters(new SecureRandom(), 256, 128);
  }

  @Test
  public void testCreateKeys() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.createKeys(new SecureRandom(), this.parameters);
  }

  @Test
  public void testCreateParameters() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.createParameters(new SecureRandom());
  }

  @Test
  public void testDecrypt() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.decrypt(this.parameters, null, null);
  }

  @Test
  public void testEncrypt() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.encrypt(new SecureRandom(), this.parameters, null, null);
  }

  @Test
  public void testGenerateProof() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final BigInteger witness = helper.generateRandom(new SecureRandom(), this.parameters.getQ());
    final Statement statement = new Statement(this.parameters.getG().modPow(witness, this.parameters.getP()), this.parameters.getG());

    final Proof proof = helper.generateProof(new SecureRandom(), this.parameters, witness, statement);
    assertThat(proof).isNotNull();
  }

  @Test
  public void testGenerateProofMultipleStatements() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final BigInteger witness = helper.generateRandom(new SecureRandom(), this.parameters.getQ());
    final Statement statement1 = new Statement(this.parameters.getG().modPow(witness, this.parameters.getP()), this.parameters.getG());
    final Statement statement2 = new Statement(this.parameters.getG().modPow(witness, this.parameters.getP()), this.parameters.getG());

    this.exception.expect(CryptographyException.class);
    helper.generateProof(new SecureRandom(), this.parameters, witness, statement1, statement2);
  }

  @Test
  public void testGenerateProofNoStatement() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final BigInteger witness = BigInteger.ONE;

    this.exception.expect(CryptographyException.class);
    helper.generateProof(new SecureRandom(), this.parameters, witness);
  }

  @Test
  public void testGenerateProofNoWitness() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final BigInteger witness = null;
    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);

    this.exception.expect(CryptographyException.class);
    helper.generateProof(new SecureRandom(), this.parameters, witness, statement);
  }

  @Test
  public void testSign() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.sign(this.parameters, null, null);
  }

  @Test
  public void testVerify() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    this.exception.expect(CryptographyException.class);
    helper.verify(this.parameters, null, null, null);
  }

  @Test
  public void testVerifyProof() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final BigInteger witness = helper.generateRandom(new SecureRandom(), this.parameters.getQ());
    final Statement statement = new Statement(this.parameters.getG().modPow(witness, this.parameters.getP()), this.parameters.getG());
    final Proof proof = helper.generateProof(new SecureRandom(), this.parameters, witness, statement);

    final boolean valid = helper.verifyProof(this.parameters, proof, statement);
    assertThat(valid).isTrue();
  }

  @Test
  public void testVerifyProofMultipleStatements() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Statement statement1 = new Statement(BigInteger.ONE, BigInteger.TEN);
    final Statement statement2 = new Statement(BigInteger.ONE, BigInteger.TEN);
    final Proof proof = new Proof();

    this.exception.expect(CryptographyException.class);
    helper.verifyProof(this.parameters, proof, statement1, statement2);
  }

  @Test
  public void testVerifyProofNoProof() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Statement statement = new Statement(BigInteger.ONE, BigInteger.TEN);
    final Proof proof = null;

    this.exception.expect(CryptographyException.class);
    helper.verifyProof(this.parameters, proof, statement);
  }

  @Test
  public void testVerifyProofNoStatement() throws Exception {
    final SchnorrAlgorithmHelper helper = new SchnorrAlgorithmHelper();
    assertThat(helper).isNotNull();

    final Proof proof = new Proof();

    this.exception.expect(CryptographyException.class);
    helper.verifyProof(this.parameters, proof);
  }
}
