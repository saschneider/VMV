/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.parameter_initialisation;

import org.bouncycastle.crypto.params.DHParameters;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.test.context.junit4.SpringRunner;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.DHParametersWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Create teller tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class CreateTellerShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File publishParams = new File("public-election-params.csv");

  private final File tellerInformation1 = new File("teller-information-1.xml");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();

    this.tellerInformation1.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateElectionTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.cryptographyHelper.createElectionKeyPair(Mockito.notNull())).thenReturn(keyPair);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    final CreateElectionParametersShellComponent.CreateElectionParametersOptions options =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", true, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(options);

    Mockito.<Class<?>>when(this.cryptographyHelper.getElectionParametersClass()).thenReturn(parameters.getClass());

    final File localTellerInformationFile = Files.createTempFile(null, null).toFile();
    Mockito.when(this.cryptographyHelper.createTeller(Mockito.isNotNull(), Mockito.anyInt(), Mockito.isNotNull(), Mockito.anyInt(), Mockito.anyInt()
    )).thenReturn(localTellerInformationFile);

    final CreateTellerShellComponent createTellerShellComponent = new CreateTellerShellComponent(this.cryptographyHelper);
    assertThat(createTellerShellComponent).isNotNull();

    assertThat(this.tellerInformation1.exists()).isFalse();

    final CreateTellerShellComponent.CreateTellerOptions createTellerOptions = new CreateTellerShellComponent.CreateTellerOptions(this.publishParams, 1,
        "localhost", 8080,
        8081, this.tellerInformation1);
    createTellerShellComponent.createTeller(createTellerOptions);

    assertThat(this.tellerInformation1.exists()).isTrue();

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createTeller(Mockito.isNotNull(), Mockito.anyInt(), Mockito.isNotNull(), Mockito.anyInt(), Mockito.anyInt()
    );

    localTellerInformationFile.delete();
  }
}
