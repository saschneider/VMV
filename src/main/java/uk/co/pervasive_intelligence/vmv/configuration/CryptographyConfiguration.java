/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.springframework.beans.factory.config.ConfigurableBeanFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import uk.co.pervasive_intelligence.vmv.ShellProgress;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.SeleneCryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.VerificatumHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.dsa.DSAAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.elgamal.ElGamalAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.ChaumPedersenAlgorithmHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.nizkp.SchnorrAlgorithmHelper;

/**
 * Cryptographic configuration.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@Configuration
public class CryptographyConfiguration {

  /*
   * Used to inject the singleton {@link ChaumPedersenAlgorithmHelper}.
   *
   * @return The {@link ChaumPedersenAlgorithmHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper() {
    return new ChaumPedersenAlgorithmHelper();
  }

  /*
   * Used to inject the singleton {@link CryptographyHelper}.
   *
   * @param messageSource The message source for localised strings.
   * @param dsaAlgorithmHelper The DSA algorithm helper.
   * @param elgamalAlgorithmHelper The ElGamal algorithm helper.
   * @param verificatumHelper The Verificatum helper.
   * @param schnorrAlgorithmHelper Schnorr algorithm helper.
   * @param chaumPedersenAlgorithmHelper Chaum-Pedersen algorithm helper.
   * @return The {@link CryptographyHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public CryptographyHelper cryptographyHelper(final MessageSource messageSource, final DSAAlgorithmHelper dsaAlgorithmHelper,
                                               final ElGamalAlgorithmHelper elgamalAlgorithmHelper, final VerificatumHelper verificatumHelper,
                                               final SchnorrAlgorithmHelper schnorrAlgorithmHelper,
                                               final ChaumPedersenAlgorithmHelper chaumPedersenAlgorithmHelper) {
    final SeleneCryptographyHelper cryptographyHelper = new SeleneCryptographyHelper(messageSource, dsaAlgorithmHelper, elgamalAlgorithmHelper, verificatumHelper,
        schnorrAlgorithmHelper, chaumPedersenAlgorithmHelper);
    cryptographyHelper.addProgressListener(new ShellProgress());

    return cryptographyHelper;
  }

  /*
   * Used to inject the singleton {@link DSAAlgorithmHelper}.
   *
   * @return The {@link DSAAlgorithmHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public DSAAlgorithmHelper dsaAlgorithmHelper() {
    return new DSAAlgorithmHelper();
  }

  /*
   * Used to inject the singleton {@link ElGamalAlgorithmHelper}.
   *
   * @return The {@link ElGamalAlgorithmHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public ElGamalAlgorithmHelper elgamalAlgorithmHelper() {
    return new ElGamalAlgorithmHelper();
  }

  /*
   * Used to inject the singleton {@link SchnorrAlgorithmHelper}.
   *
   * @return The {@link SchnorrAlgorithmHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public SchnorrAlgorithmHelper schnorrAlgorithmHelper() {
    return new SchnorrAlgorithmHelper();
  }

  /*
   * Used to inject the singleton {@link VerificatumHelper}.
   *
   * @return The {@link VerificatumHelper}.
   */
  @Bean
  @Scope(value = ConfigurableBeanFactory.SCOPE_SINGLETON)
  public VerificatumHelper verificatumHelper() {
    return new VerificatumHelper();
  }
}
