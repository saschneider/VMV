/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.jline.reader.History;
import org.jline.reader.LineReader;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.shell.jline.PromptProvider;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.util.ReflectionTestUtils;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JLine configuration tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class JLineConfigurationTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Mock
  private History history;

  @Mock
  private LineReader lineReader;

  @Test
  public void testHistory() {
    final JLineConfiguration configuration = new JLineConfiguration();
    final History history = configuration.history(this.lineReader, "history.file");
    assertThat(history).isNotNull();
  }

  @Test
  public void testOnContextClosedEvent() throws Exception {
    final JLineConfiguration configuration = new JLineConfiguration();
    ReflectionTestUtils.setField(configuration, "history", this.history);

    configuration.onContextClosedEvent(null);
    Mockito.verify(this.history).save();
  }

  @Test
  public void testPromptProvider() {
    final JLineConfiguration configuration = new JLineConfiguration();
    final PromptProvider promptProvider = configuration.promptProvider("prompt:> ");
    assertThat(promptProvider).isNotNull();
  }
}
