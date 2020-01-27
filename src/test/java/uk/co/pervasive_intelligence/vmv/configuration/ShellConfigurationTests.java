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
import org.mockito.Mockito;
import org.springframework.context.MessageSource;
import org.springframework.shell.Command;
import org.springframework.shell.MethodTarget;
import org.springframework.shell.Shell;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.ReflectionUtils;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * JLine configuration tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@RunWith(SpringRunner.class)
public class ShellConfigurationTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Mock
  private MessageSource messageSource;

  @Mock
  private Shell shell;

  @Test
  public void testLocaliseCommands() {
    final String name = "name";
    final String description = "description";
    final String group = "group";
    final Command.Help help = new Command.Help(description, group);
    final Method method = ReflectionUtils.findMethod(ShellConfigurationTests.class, "testLocaliseCommands");
    final MethodTarget methodTarget = new MethodTarget(method, new Object(), help, null);
    final Map<String, MethodTarget> commands = Collections.singletonMap(name, methodTarget);
    Mockito.when(this.shell.listCommands()).thenReturn(commands);

    final ShellConfiguration configuration = new ShellConfiguration(this.shell, this.messageSource);
    assertThat(configuration).isNotNull();

    configuration.localiseCommands();

    Mockito.verify(this.shell).listCommands();
    Mockito.verify(this.messageSource, Mockito.times(2)).getMessage(Mockito.isNotNull(), Mockito.isNull(), Mockito.isNull());
  }
}
