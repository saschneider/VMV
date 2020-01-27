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
import uk.co.pervasive_intelligence.vmv.cryptography.data.TrackerNumber;

import java.io.File;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Create tracker number tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class CreateTrackerNumbersShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File outputKeys = new File("election-keys.csv");

  private final File publishKeys = new File("public-election-keys.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishTrackerNumbers = new File("publish-tracker-numbers.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
    this.outputKeys.delete();
    this.publishKeys.delete();

    this.publishTrackerNumbers.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCreateTrackerNumbers() throws Exception {
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

    final CreateTrackerNumbersShellComponent createTrackerNumbersShellComponent = new CreateTrackerNumbersShellComponent(this.cryptographyHelper);
    assertThat(createTrackerNumbersShellComponent).isNotNull();

    final int numberOfVoters = 10;
    final Set<TrackerNumber> trackerNumbers = new HashSet<>();
    final byte[] encryptedTrackerNumberInGroup = new byte[10];

    for (int i = 0; i < numberOfVoters; i++) {
      trackerNumbers.add(new TrackerNumber(i + 1, BigInteger.valueOf(i + 1), encryptedTrackerNumberInGroup));
    }

    Mockito.when(this.cryptographyHelper.createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt())).thenReturn(trackerNumbers);

    assertThat(this.publishTrackerNumbers.exists()).isFalse();

    final CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions createTrackerNumbersOptions =
        new CreateTrackerNumbersShellComponent.CreateTrackerNumbersOptions(Arrays.asList(this.publishParams, this.publishKeys), numberOfVoters,
            this.publishTrackerNumbers);
    createTrackerNumbersShellComponent.createTrackerNumbers(createTrackerNumbersOptions);

    assertThat(this.publishTrackerNumbers.exists()).isTrue();

    final List<TrackerNumber> publishTrackerNumbers = (List<TrackerNumber>) createTrackerNumbersShellComponent.readCSV(this.publishTrackerNumbers,
        TrackerNumber.class);
    assertThat(publishTrackerNumbers).isNotNull();
    assertThat(publishTrackerNumbers.size()).isEqualTo(numberOfVoters);

    for (int i = 0; i < numberOfVoters; i++) {
      assertThat(publishTrackerNumbers.get(i).getTrackerNumber()).isEqualTo(i + 1);
      assertThat(publishTrackerNumbers.get(i).getTrackerNumberInGroup()).isEqualTo(BigInteger.valueOf(i + 1));
      assertThat(publishTrackerNumbers.get(i).getEncryptedTrackerNumberInGroup()).isEqualTo(encryptedTrackerNumberInGroup);
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).createElectionKeyPair(Mockito.notNull(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper, Mockito.times(2)).getElectionParametersClass();
    Mockito.verify(this.cryptographyHelper).createTrackerNumbers(Mockito.isNotNull(), Mockito.isNotNull(), Mockito.anyInt());
  }
}
