/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ciphertext tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class CipherTextTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testCipherText() throws Exception {
    final BigInteger alpha = BigInteger.ONE;
    final BigInteger beta = BigInteger.TEN;

    final CipherText cipherText = new CipherText(alpha, beta);
    assertThat(cipherText).isNotNull();
    assertThat(cipherText.getAlpha()).isEqualTo(alpha);
    assertThat(cipherText.getBeta()).isEqualTo(beta);

    final byte[] bytes = cipherText.toByteArray();
    assertThat(bytes).isNotNull();

    final CipherText read = new CipherText(bytes);
    assertThat(read).isNotNull();
    assertThat(read.getAlpha()).isEqualTo(alpha);
    assertThat(read.getBeta()).isEqualTo(beta);
  }
}
