/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.springframework.context.MessageSource;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.VerificatumHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.ChaumPedersenAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.SchnorrAlgorithmHelper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Cryptographic configuration tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class CryptographyConfigurationTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Mock
  private ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper;

  @Mock
  private DSAAlgorithmHelper dsaAlgorithmHelper;

  @Mock
  private ElGamalAlgorithmHelper elgamalAlgorithmHelper;

  @Mock
  private MessageSource messageSource;

  @Mock
  private SchnorrAlgorithmHelper schnorrAlgorithmHelper;

  @Mock
  private VerificatumHelper verificatumHelper;

  @Test
  public void testCryptographyHelper() {
    final CryptographyConfiguration configuration = new CryptographyConfiguration();
    final CryptographyHelper helper = configuration.cryptographyHelper(this.messageSource, this.dsaAlgorithmHelper, this.elgamalAlgorithmHelper,
        this.verificatumHelper, this.schnorrAlgorithmHelper, this.chaumPedersenAlgorithmHelper);
    assertThat(helper).isNotNull();
  }

  @Test
  public void testDSAAlgorithmHelper() {
    final CryptographyConfiguration configuration = new CryptographyConfiguration();
    final DSAAlgorithmHelper helper = configuration.dsaAlgorithmHelper();
    assertThat(helper).isNotNull();
  }

  @Test
  public void testElGamalAlgorithmHelper() {
    final CryptographyConfiguration configuration = new CryptographyConfiguration();
    final ElGamalAlgorithmHelper helper = configuration.elgamalAlgorithmHelper();
    assertThat(helper).isNotNull();
  }

  @Test
  public void testVerificatumHelper() {
    final CryptographyConfiguration configuration = new CryptographyConfiguration();
    final VerificatumHelper helper = configuration.verificatumHelper();
    assertThat(helper).isNotNull();
  }
}
