/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import com.fasterxml.jackson.annotation.JsonView;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Base shell component tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class BaseShellComponentTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  private final File outputFile = new File("output-file.csv");

  @Before
  @After
  public void setUp() {
    this.outputFile.delete();
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCSVExclude() throws Exception {
    final List<TestContent> writeContent = new ArrayList<>();
    writeContent.add(new TestContent("first", 1, new byte[10]));
    writeContent.add(new TestContent("second", 2, new byte[10]));

    assertThat(this.outputFile.exists()).isFalse();

    final TestBaseShellComponent baseShellComponent = new TestBaseShellComponent();
    baseShellComponent.writeCSV(this.outputFile, TestContent.class, writeContent, JacksonViews.Public.class);

    assertThat(this.outputFile.exists()).isTrue();

    final List<TestContent> readContent = (List<TestContent>) baseShellComponent.readCSV(this.outputFile, TestContent.class, JacksonViews.Public.class);
    assertThat(readContent).isNotNull();
    assertThat(readContent.size()).isEqualTo(writeContent.size());

    for (int i = 0; i < writeContent.size(); i++) {
      assertThat(readContent.get(i).getName()).isEqualTo(writeContent.get(i).getName());
      assertThat(readContent.get(i).getValue()).isEqualTo(writeContent.get(i).getValue());
      assertThat(readContent.get(i).getPrivateKey()).isNull();
    }
  }

  @Test
  @SuppressWarnings("unchecked")
  public void testCSVNoExclude() throws Exception {
    final List<TestContent> writeContent = new ArrayList<>();
    writeContent.add(new TestContent("first", 1, new byte[10]));
    writeContent.add(new TestContent("second", 2, new byte[10]));

    assertThat(this.outputFile.exists()).isFalse();

    final TestBaseShellComponent baseShellComponent = new TestBaseShellComponent();
    baseShellComponent.writeCSV(this.outputFile, TestContent.class, writeContent);

    assertThat(this.outputFile.exists()).isTrue();

    final List<TestContent> readContent = (List<TestContent>) baseShellComponent.readCSV(this.outputFile, TestContent.class);
    assertThat(readContent).isNotNull();
    assertThat(readContent.size()).isEqualTo(writeContent.size());

    for (int i = 0; i < writeContent.size(); i++) {
      assertThat(readContent.get(i).getName()).isEqualTo(writeContent.get(i).getName());
      assertThat(readContent.get(i).getValue()).isEqualTo(writeContent.get(i).getValue());
      assertThat(readContent.get(i).getPrivateKey()).isNotEmpty();
    }
  }

  /**
   * Base shell component implementation.
   */
  public static class TestBaseShellComponent extends BaseShellComponent {

  }

  /**
   * Content implementation.
   */
  public static class TestContent {

    @JsonView(JacksonViews.Public.class)
    private String name;

    @JsonView(JacksonViews.Private.class)
    private byte[] privateKey;

    @JsonView(JacksonViews.Public.class)
    private int value;

    private TestContent() {

    }

    public TestContent(final String name, final int value, final byte[] privateKey) {
      this.name = name;
      this.value = value;
      this.privateKey = privateKey;
    }

    public String getName() {
      return this.name;
    }

    public byte[] getPrivateKey() {
      return this.privateKey;
    }

    public int getValue() {
      return this.value;
    }
  }
}

