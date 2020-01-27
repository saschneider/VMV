/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.MessageSource;
import org.springframework.core.annotation.Order;
import uk.co.pervasive_intelligence.vmv.cryptography.CryptographyHelper;

/**
 * Spring Boot application entry point. Note that this bean has an order of 0 to make sure {@link ApplicationRunner} is run before the shell.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
@SpringBootApplication
@Order(value = 0)
public class VMVApplication implements ApplicationRunner {

  /** The cryptography helper. */
  private final CryptographyHelper cryptographyHelper;

  /** The source for messages. */
  private final MessageSource messageSource;

  /**
   * Auto wired constructor with dependencies.
   *
   * @param messageSource      The source for messages.
   * @param cryptographyHelper The cryptography helper.
   */
  public VMVApplication(final MessageSource messageSource, final CryptographyHelper cryptographyHelper) {
    this.messageSource = messageSource;
    this.cryptographyHelper = cryptographyHelper;
  }

  /**
   * Main entry point for application. Starts-up Spring.
   *
   * @param args The command line arguments.
   */
  public static void main(final String[] args) {
    final SpringApplication application = new SpringApplication(VMVApplication.class);
    application.run(args);
  }

  /**
   * Callback used when the application has started.
   *
   * @param args Incoming application arguments.
   */
  @Override
  public void run(final ApplicationArguments args) {
    // Output cryptographic information to the console.
    System.out.println(this.messageSource.getMessage("application.cryptography.unlimited_strength",
        new Object[] {this.cryptographyHelper.isUnlimitedStrength()}, null));
    System.out.println();
  }
}
