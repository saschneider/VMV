/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import org.jline.reader.History;
import org.jline.reader.LineReader;
import org.jline.reader.impl.history.DefaultHistory;
import org.jline.utils.AttributedString;
import org.jline.utils.AttributedStyle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.event.ContextClosedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.shell.jline.JLineShellAutoConfiguration;
import org.springframework.shell.jline.PromptProvider;

import java.io.IOException;
import java.nio.file.Paths;

/**
 * JLine configuration: used by Spring Shell to read commands from the prompt. Based upon content of {@link JLineShellAutoConfiguration}.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@Configuration
public class JLineConfiguration {

  /** Lazily load the history as we are creating it as a bean in this class. */
  @Autowired
  @Lazy
  private History history;

  /**
   * Create the history object using an explicit property value for the file name.
   *
   * @param lineReader  The injected {@link LineReader}.
   * @param historyPath The path to the history file.
   * @return The new {@link History} object.
   */
  @Bean
  public History history(final LineReader lineReader, @Value("${spring.shell.history.file}") final String historyPath) {
    lineReader.setVariable(LineReader.HISTORY_FILE, Paths.get(historyPath));
    return new DefaultHistory(lineReader);
  }

  /**
   * Make sure we flush the history when the application exits.
   *
   * @param event The exit event.
   * @throws IOException If the history could not be flushed.
   */
  @EventListener
  public void onContextClosedEvent(final ContextClosedEvent event) throws IOException {
    this.history.save();
  }

  /**
   * Create the prompt provider using a property for the prompt.
   *
   * @param prompt The prompt property.
   * @return The created prompt provider.
   */
  @Bean
  public PromptProvider promptProvider(@Value("${spring.shell.prompt}") final String prompt) {
    return () -> new AttributedString(prompt, AttributedStyle.DEFAULT.foreground(AttributedStyle.YELLOW));
  }
}
