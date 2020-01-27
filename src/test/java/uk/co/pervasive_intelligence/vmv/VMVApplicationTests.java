/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import org.jline.utils.AttributedStringBuilder;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.shell.ExitRequest;
import org.springframework.shell.Shell;
import org.springframework.shell.jline.InteractiveShellApplicationRunner;
import org.springframework.shell.jline.ScriptShellApplicationRunner;
import org.springframework.test.context.junit4.SpringRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * VMV application tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
@SpringBootTest(properties = {
    InteractiveShellApplicationRunner.SPRING_SHELL_INTERACTIVE_ENABLED + "=" + false,
    ScriptShellApplicationRunner.SPRING_SHELL_SCRIPT_ENABLED + "=" + false
})
public class VMVApplicationTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Autowired
  private Shell shell;

  @Test
  public void testClear() {
    final Object clear = this.shell.evaluate(() -> "clear");
    assertThat(clear).isNull();
  }

  @Test
  public void testExit() {
    final Object exit = this.shell.evaluate(() -> "exit");
    assertThat(exit).isNotNull();
    assertThat(exit).isInstanceOf(ExitRequest.class);
  }

  @Test
  public void testHelp() {
    final Object help = this.shell.evaluate(() -> "help");
    assertThat(help).isNotNull();
    assertThat(help).isInstanceOf(AttributedStringBuilder.class);
  }
}
