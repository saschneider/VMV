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
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Merge teller tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class MergeTellerShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File localTellerInformation1 = new File("local-1.xml");

  private final File localTellerInformation2 = new File("local-2.xml");

  private final File localTellerInformation3 = new File("local-3.xml");

  private final File localTellerInformation4 = new File("local-4.xml");

  private final File publishParams = new File("public-election-params.csv");

  private final File tellerInformation1 = new File("teller-information-1.xml");

  private final File tellerInformation2 = new File("teller-information-2.xml");

  private final File tellerInformation3 = new File("teller-information-3.xml");

  private final File tellerInformation4 = new File("teller-information-4.xml");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();

    this.tellerInformation1.delete();
    this.tellerInformation2.delete();
    this.tellerInformation3.delete();
    this.tellerInformation4.delete();

    this.localTellerInformation1.delete();
    this.localTellerInformation2.delete();
    this.localTellerInformation3.delete();
    this.localTellerInformation4.delete();
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

    createTellerShellComponent.createTeller(new CreateTellerShellComponent.CreateTellerOptions(this.publishParams, 1, "localhost", 8081, 4041,
        this.tellerInformation1));
    createTellerShellComponent.createTeller(new CreateTellerShellComponent.CreateTellerOptions(this.publishParams, 2, "localhost", 8082, 4042,
        this.tellerInformation2));
    createTellerShellComponent.createTeller(new CreateTellerShellComponent.CreateTellerOptions(this.publishParams, 3, "localhost", 8083, 4043,
        this.tellerInformation3));
    createTellerShellComponent.createTeller(new CreateTellerShellComponent.CreateTellerOptions(this.publishParams, 4, "localhost", 8084, 4044,
        this.tellerInformation4));

    final MergeTellerShellComponent mergeTellerShellComponent = new MergeTellerShellComponent(this.cryptographyHelper);
    assertThat(mergeTellerShellComponent).isNotNull();

    final int teller = 1;
    Mockito.when(this.cryptographyHelper.getTellerInformationFiles(Mockito.isNotNull(), Mockito.eq(teller))).thenReturn(new File[] {
        this.localTellerInformation1, this.localTellerInformation2, this.localTellerInformation3, this.localTellerInformation4
    });

    assertThat(this.localTellerInformation1.exists()).isFalse();
    assertThat(this.localTellerInformation2.exists()).isFalse();
    assertThat(this.localTellerInformation3.exists()).isFalse();
    assertThat(this.localTellerInformation4.exists()).isFalse();

    final MergeTellerShellComponent.MergeTellerOptions mergeTellerOptions = new MergeTellerShellComponent.MergeTellerOptions(this.publishParams, 1,
        Arrays.asList(this.tellerInformation1, this.tellerInformation2, this.tellerInformation3, this.tellerInformation4));
    mergeTellerShellComponent.mergeTeller(mergeTellerOptions);

    assertThat(this.localTellerInformation1.exists()).isTrue();
    assertThat(this.localTellerInformation2.exists()).isTrue();
    assertThat(this.localTellerInformation3.exists()).isTrue();
    assertThat(this.localTellerInformation4.exists()).isTrue();

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(4)).createTeller(Mockito.isNotNull(), Mockito.anyInt(), Mockito.isNotNull(), Mockito.anyInt(),
        Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).mergeTeller(Mockito.isNotNull(), Mockito.anyInt(), Mockito.isNotNull(), Mockito.isNotNull(), Mockito.isNotNull(),
        Mockito.isNotNull());

    localTellerInformationFile.delete();
  }
}
