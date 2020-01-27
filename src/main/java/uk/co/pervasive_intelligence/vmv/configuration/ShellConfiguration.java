/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.MessageSource;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.annotation.Configuration;
import org.springframework.shell.Command;
import org.springframework.shell.MethodTarget;
import org.springframework.shell.Shell;
import org.springframework.util.ReflectionUtils;

import javax.annotation.PostConstruct;
import java.lang.reflect.Field;
import java.util.Map;

/**
 * Shell configuration.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@Configuration
public class ShellConfiguration {

  /** Shell help field. */
  private static final String FIELD_HELP = "help";

  /** Logger. */
  private static final Logger LOG = LoggerFactory.getLogger(ShellConfiguration.class);

  /** The source for messages. */
  private final MessageSource messageSource;

  /** The Spring shell. */
  private final Shell shell;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param shell         The Spring shell.
   * @param messageSource The source for messages.
   */
  public ShellConfiguration(final Shell shell, final MessageSource messageSource) {
    this.shell = shell;
    this.messageSource = messageSource;
  }

  /**
   * Called after the application has been created to make sure that all shell commands are appropriately localised. This method uses reflection to localise the
   * help and group text for each command.
   */
  @PostConstruct
  public void localiseCommands() {
    // Get the commands. This is the best we can do to get at them.
    final Map<String, MethodTarget> commands = this.shell.listCommands();

    // For each command, attempt to find a localised version of the help and group.
    for (final MethodTarget methodTarget : commands.values()) {
      try {
        final Field field = ReflectionUtils.findField(MethodTarget.class, FIELD_HELP);

        if (field != null) {
          field.setAccessible(true);
          final Command.Help help = (Command.Help) ReflectionUtils.getField(field, methodTarget);

          if (help != null) {
            final String description = help.getDescription();
            final String group = help.getGroup();
            String localisedDescription = null;
            String localisedGroup = null;

            if (description != null) {
              try {
                localisedDescription = this.messageSource.getMessage(description, null, null);
              }
              catch (final NoSuchMessageException e) {
                localisedDescription = description;
              }
            }

            if (group != null) {
              try {
                localisedGroup = this.messageSource.getMessage(group, null, null);
              }
              catch (final NoSuchMessageException e) {
                localisedGroup = group;
              }
            }

            // Use reflection to set the values as we cannot access the map directly.
            if ((localisedDescription != null) && (localisedGroup != null)) {
              ReflectionUtils.setField(field, methodTarget, new Command.Help(localisedDescription, localisedGroup));
            }
            else if (localisedDescription != null) {
              ReflectionUtils.setField(field, methodTarget, new Command.Help(localisedDescription));
            }
          }
        }
      }
      catch (final Exception e) {
        LOG.error("Could not localise command {}", methodTarget, e);
      }
    }
  }
}
