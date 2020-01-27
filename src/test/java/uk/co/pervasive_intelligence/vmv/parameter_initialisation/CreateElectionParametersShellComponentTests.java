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

import java.io.File;
import java.math.BigInteger;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Create election tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class CreateElectionParametersShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File publishParams = new File("public-election-params.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateElectionNoTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    assertThat(createElectionParametersShellComponent).isNotNull();

    assertThat(this.publishParams.exists()).isFalse();

    final CreateElectionParametersShellComponent.CreateElectionParametersOptions options =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", true, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(options);

    assertThat(this.publishParams.exists()).isTrue();

    final List<DHParametersWrapper> publishParameters = (List<DHParametersWrapper>) createElectionParametersShellComponent.readCSV(this.publishParams,
        DHParametersWrapper.class);
    assertThat(publishParameters).isNotNull();
    assertThat(publishParameters.size()).isEqualTo(1);
    assertThat(publishParameters.get(0).getG()).isEqualTo(parameters.getG());
    assertThat(publishParameters.get(0).getP()).isEqualTo(parameters.getP());
    assertThat(publishParameters.get(0).getQ()).isEqualTo(parameters.getQ());
    assertThat(publishParameters.get(0).getName()).isEqualTo(parameters.getName());
    assertThat(publishParameters.get(0).getNumberOfTellers()).isEqualTo(0);
    assertThat(publishParameters.get(0).getThresholdTellers()).isEqualTo(0);

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateElectionTellers() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    assertThat(createElectionParametersShellComponent).isNotNull();

    assertThat(this.publishParams.exists()).isFalse();

    final CreateElectionParametersShellComponent.CreateElectionParametersOptions options =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", false, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(options);

    assertThat(this.publishParams.exists()).isTrue();

    final List<DHParametersWrapper> publishParameters = (List<DHParametersWrapper>) createElectionParametersShellComponent.readCSV(this.publishParams,
        DHParametersWrapper.class);
    assertThat(publishParameters).isNotNull();
    assertThat(publishParameters.size()).isEqualTo(1);
    assertThat(publishParameters.get(0).getG()).isEqualTo(parameters.getG());
    assertThat(publishParameters.get(0).getP()).isEqualTo(parameters.getP());
    assertThat(publishParameters.get(0).getQ()).isEqualTo(parameters.getQ());
    assertThat(publishParameters.get(0).getName()).isEqualTo(parameters.getName());
    assertThat(publishParameters.get(0).getNumberOfTellers()).isEqualTo(parameters.getNumberOfTellers());
    assertThat(publishParameters.get(0).getThresholdTellers()).isEqualTo(parameters.getThresholdTellers());

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
  }
}
