/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
 */
package uk.co.pervasive_intelligence.vmv.cryptography;

import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import java.math.BigInteger;
import java.security.SecureRandom;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base algorithm helper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class BaseHelperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testDigestForLength() {
    final BaseHelper helper = new BaseHelper() {
    };
    assertThat(helper).isNotNull();

    assertThat(helper.digestForLength(160)).isInstanceOf(SHA1Digest.class);
    assertThat(helper.digestForLength(256)).isInstanceOf(SHA256Digest.class);
    assertThat(helper.digestForLength(384)).isInstanceOf(SHA384Digest.class);
    assertThat(helper.digestForLength(512)).isInstanceOf(SHA512Digest.class);
  }

  @Test
  public void testGenerateRandom() {
    final BaseHelper helper = new BaseHelper() {
    };
    assertThat(helper).isNotNull();

    final BigInteger limit = BigInteger.TEN;

    for (int i = 0; i < 10; i++) {
      final BigInteger value = helper.generateRandom(new SecureRandom(), limit);
      assertThat(value).isNotNull();
      assertThat(value.compareTo(BigInteger.ONE)).isGreaterThanOrEqualTo(0);
      assertThat(value.compareTo(BigInteger.TEN)).isEqualTo(-1);
    }
  }

  @Test
  public void testHash() {
    final BaseHelper helper = new BaseHelper() {
    };
    assertThat(helper).isNotNull();

    final BigInteger[] values = new BigInteger[] {BigInteger.ONE, BigInteger.TEN, BigInteger.ZERO};

    final BigInteger hash1 = helper.hash(512, values);
    assertThat(hash1).isNotNull();

    final BigInteger hash2 = helper.hash(512, values);
    assertThat(hash2).isNotNull();

    assertThat(hash1).isEqualTo(hash2);
  }
}
