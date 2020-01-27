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
import uk.co.pervasive_intelligence.vmv.JacksonViews;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.DHParametersWrapper;
import uk.co.pervasive_intelligence.vmv.cryptography.data.KeyPair;
import uk.co.pervasive_intelligence.vmv.cryptography.data.VoterKeyPairs;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Voter create keys tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class VoterCreateKeysShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File outputKeys = new File("election-keys.csv");

  private final File outputVotersKeys = new File("voters-keys.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishVotersKeys = new File("public-voters-keys.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
    this.outputKeys.delete();
    this.publishKeys.delete();

    this.outputVotersKeys.delete();
    this.publishVotersKeys.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateVoters() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final BigInteger privateKey = BigInteger.valueOf(123);
    final BigInteger publicKey = BigInteger.valueOf(456);
    final KeyPair keyPair = new KeyPair(privateKey, publicKey);
    Mockito.when(this.cryptographyHelper.createElectionKeyPair(Mockito.notNull(), Mockito.anyInt())).thenReturn(keyPair);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    final CreateElectionParametersShellComponent.CreateElectionParametersOptions createElectionParametersOptions =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", true, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(createElectionParametersOptions);

    Mockito.<Class<?>>when(this.cryptographyHelper.getElectionParametersClass()).thenReturn(parameters.getClass());

    final CreateElectionKeysShellComponent createElectionKeysShellComponent = new CreateElectionKeysShellComponent(this.cryptographyHelper);
    final CreateElectionKeysShellComponent.CreateElectionKeysOptions createElectionKeysOptions =
        new CreateElectionKeysShellComponent.CreateElectionKeysOptions(this.publishParams, 0, this.outputKeys, this.publishKeys);
    createElectionKeysShellComponent.createElectionKeys(createElectionKeysOptions);

    final VoterCreateKeysShellComponent voterCreateKeysShellComponent = new VoterCreateKeysShellComponent(this.cryptographyHelper);
    assertThat(voterCreateKeysShellComponent).isNotNull();

    final int numberOfVoters = 1;
    final List<VoterKeyPairs> keyPairs = new ArrayList<>();

    for (int i = 0; i < numberOfVoters; i++) {
      keyPairs.add(new VoterKeyPairs(
          new KeyPair(BigInteger.valueOf(i + 1), BigInteger.valueOf(i + 2)), new KeyPair(BigInteger.valueOf(i + 3), BigInteger.valueOf(i + 4))));
    }

    Mockito.when(this.cryptographyHelper.createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull())).thenReturn(keyPairs);

    assertThat(this.outputVotersKeys.exists()).isFalse();
    assertThat(this.publishVotersKeys.exists()).isFalse();

    final VoterCreateKeysShellComponent.VoterCreateKeysOptions voterCreateKeysOptions =
        new VoterCreateKeysShellComponent.VoterCreateKeysOptions(this.publishParams, this.outputVotersKeys, this.publishVotersKeys);
    voterCreateKeysShellComponent.voterCreateKeys(voterCreateKeysOptions);

    assertThat(this.outputVotersKeys.exists()).isTrue();
    assertThat(this.publishVotersKeys.exists()).isTrue();

    final List<VoterKeyPairs> outputVotersParameters =
        (List<VoterKeyPairs>) voterCreateKeysShellComponent.readCSV(this.outputVotersKeys, VoterKeyPairs.class);
    assertThat(outputVotersParameters).isNotNull();
    assertThat(outputVotersParameters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(outputVotersParameters.get(i).getTrapdoorKeyPair()).isNotNull();
      assertThat(outputVotersParameters.get(i).getTrapdoorKeyPair().getPrivateKey()).isEqualTo(keyPairs.get(i).getTrapdoorKeyPair().getPrivateKey());
      assertThat(outputVotersParameters.get(i).getTrapdoorKeyPair().getPublicKey()).isEqualTo(keyPairs.get(i).getTrapdoorKeyPair().getPublicKey());

      assertThat(outputVotersParameters.get(i).getSignatureKeyPair()).isNotNull();
      assertThat(outputVotersParameters.get(i).getSignatureKeyPair().getPrivateKey()).isEqualTo(keyPairs.get(i).getSignatureKeyPair().getPrivateKey());
      assertThat(outputVotersParameters.get(i).getSignatureKeyPair().getPublicKey()).isEqualTo(keyPairs.get(i).getSignatureKeyPair().getPublicKey());
    }

    final List<VoterKeyPairs> publishVotersParameters =
        (List<VoterKeyPairs>) voterCreateKeysShellComponent.readCSV(this.publishVotersKeys, VoterKeyPairs.class, JacksonViews.Public.class);
    assertThat(publishVotersParameters).isNotNull();
    assertThat(publishVotersParameters.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publishVotersParameters.get(i).getTrapdoorKeyPair()).isNotNull();
      assertThat(publishVotersParameters.get(i).getTrapdoorKeyPair().getPrivateKey()).isNull();
      assertThat(publishVotersParameters.get(i).getTrapdoorKeyPair().getPublicKey()).isEqualTo(keyPairs.get(i).getTrapdoorKeyPair().getPublicKey());

      assertThat(publishVotersParameters.get(i).getSignatureKeyPair()).isNotNull();
      assertThat(publishVotersParameters.get(i).getSignatureKeyPair().getPrivateKey()).isNull();
      assertThat(publishVotersParameters.get(i).getSignatureKeyPair().getPublicKey()).isEqualTo(keyPairs.get(i).getSignatureKeyPair().getPublicKey());
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(2)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createVotersKeyPairs(Mockito.anyInt(), Mockito.isNotNull());
  }
}
