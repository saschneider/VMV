/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2019
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
import uk.co.pervasive_intelligence.vmv.cryptography.data.VoteOption;

import java.io.File;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Map vote options tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class MapVoteOptionsShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File ersVoteOptions = new File("ers-vote-options.csv");

  private final File publishParams = new File("public-election-params.csv");

  private final File publishVoteOptions = new File("public-vote-options.csv");

  @Mock
  private CryptographyHelper cryptographyHelper;

  @Before
  @After
  public void setUp() {
    this.publishParams.delete();
    this.ersVoteOptions.delete();
    this.publishVoteOptions.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testMapVoteOptions() throws Exception {
    final DHParameters object = new DHParameters(BigInteger.TEN, BigInteger.TEN, BigInteger.ZERO, 1, 2, BigInteger.ONE, null);
    final DHParametersWrapper parameters = new DHParametersWrapper(object);
    Mockito.when(this.cryptographyHelper.createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt())).thenReturn(parameters);

    final CreateElectionParametersShellComponent createElectionParametersShellComponent = new CreateElectionParametersShellComponent(this.cryptographyHelper);
    final CreateElectionParametersShellComponent.CreateElectionParametersOptions createElectionParametersOptions =
        new CreateElectionParametersShellComponent.CreateElectionParametersOptions(this.publishParams, "Election", true, 4, 3, 1024, 160, 128);
    createElectionParametersShellComponent.createElectionParameters(createElectionParametersOptions);

    Mockito.<Class<?>>when(this.cryptographyHelper.getElectionParametersClass()).thenReturn(parameters.getClass());

    final MapVoteOptionsShellComponent mapVoteOptionsShellComponent = new MapVoteOptionsShellComponent(this.cryptographyHelper);
    assertThat(mapVoteOptionsShellComponent).isNotNull();

    final int numberOfVoteOptions = 100;
    final List<VoteOption> ersVoteOptions = new ArrayList<>();

    for (int i = 0; i < numberOfVoteOptions; i++) {
      final VoteOption voteOption = new VoteOption(Integer.toString(numberOfVoteOptions + i));
      ersVoteOptions.add(voteOption);
    }

    mapVoteOptionsShellComponent.writeCSV(this.ersVoteOptions, VoteOption.class, ersVoteOptions, JacksonViews.ERSImport.class);

    Mockito.doAnswer(invocation -> {
      List<VoteOption> voterOptions = invocation.getArgument(1);

      for (int i = 0; i < voterOptions.size(); i++) {
        voterOptions.get(i).setOptionNumberInGroup(BigInteger.valueOf(i));
      }

      return null;
    }).when(this.cryptographyHelper).mapVoteOptions(Mockito.isNotNull(), Mockito.isNotNull());

    assertThat(this.publishVoteOptions.exists()).isFalse();

    final MapVoteOptionsShellComponent.MapVoteOptionsOptions mapVoteOptionsOptions =
        new MapVoteOptionsShellComponent.MapVoteOptionsOptions(this.publishParams, this.ersVoteOptions, this.publishVoteOptions);
    mapVoteOptionsShellComponent.mapVoteOptions(mapVoteOptionsOptions);

    assertThat(this.publishVoteOptions.exists()).isTrue();

    final List<VoteOption> publishVoteOptions = (List<VoteOption>) mapVoteOptionsShellComponent.readCSV(this.publishVoteOptions, VoteOption.class,
        JacksonViews.Public.class);
    assertThat(publishVoteOptions).isNotNull();
    assertThat(publishVoteOptions.size()).isEqualTo(ersVoteOptions.size());

    for (final VoteOption publishVoteOption : publishVoteOptions) {
      assertThat(publishVoteOption.getOption()).isNotNull();
      assertThat(publishVoteOption.getOptionNumberInGroup()).isNotNull();
    }

    Mockito.verify(this.cryptographyHelper).createElectionParameters(Mockito.anyInt(), Mockito.anyInt(), Mockito.anyInt());
    Mockito.verify(this.cryptographyHelper).mapVoteOptions(Mockito.notNull(), Mockito.notNull());
  }
}
