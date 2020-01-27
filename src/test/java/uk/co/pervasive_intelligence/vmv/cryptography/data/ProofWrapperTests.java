/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.cryptography.data;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import uk.co.pervasive_intelligence.vmv.BaseTestCase;

import java.io.File;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Proof wrapper tests.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class ProofWrapperTests extends BaseTestCase {

  @Rule
  public final ExpectedException exception = ExpectedException.none();

  @Test
  public void testProofWrapper() {
    final Object object = new Object();
    final File proofFile = new File("proof.zip");

    final ProofWrapper<Object> wrapper = new ProofWrapper<>(object, proofFile);
    assertThat(wrapper).isNotNull();
    assertThat(wrapper.getObject()).isEqualTo(object);
    assertThat(wrapper.getProofFile()).isEqualTo(proofFile);
  }
}
