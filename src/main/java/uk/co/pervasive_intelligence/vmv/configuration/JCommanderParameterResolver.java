/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv.configuration;

import com.beust.jcommander.*;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.MethodParameter;
import org.springframework.shell.ParameterDescription;
import org.springframework.shell.*;
import org.springframework.util.ReflectionUtils;

import javax.validation.Validation;
import javax.validation.Validator;
import javax.validation.ValidatorFactory;
import javax.validation.metadata.BeanDescriptor;
import java.lang.annotation.Annotation;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.springframework.shell.Utils.unCamelify;

/**
 * Modified from {@link org.springframework.shell.jcommander.JCommanderParameterResolver}. This class has been modified to provide a different setup of the {@link
 * JCommander} object.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public class JCommanderParameterResolver implements ParameterResolver {

  /** JCommander annotations. */
  private static final Collection<Class<? extends Annotation>> JCOMMANDER_ANNOTATIONS = Arrays.asList(Parameter.class,
      DynamicParameter.class, ParametersDelegate.class);

  /** Parameter validator. */
  private Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

  /**
   * Invoked during TAB completion. If the {@link CompletionContext} can be interpreted as the start of a supported {@link MethodParameter} value, one or several
   * proposals should be returned.
   *
   * @param parameter The parameters being parsed.
   * @param context   The completion context.
   * @return Possible completions.
   */
  @Override
  public List<CompletionProposal> complete(final MethodParameter parameter, final CompletionContext context) {
    final JCommander jCommander = this.createJCommander(parameter);
    final List<String> words = context.getWords();

    try {
      jCommander.parseWithoutValidation(words.toArray(new String[0]));
    }
    catch (final ParameterException ignored) {
      // Exception here certainly means current buffer is not parseable in full. Better to bail out now.
      return Collections.emptyList();
    }

    return this.streamAllJCommanderDescriptions(jCommander)
        .filter(p -> !p.isAssigned())
        .flatMap(p -> Arrays.stream(p.getParameter().names()))
        .map(CompletionProposal::new)
        .collect(Collectors.toList());
  }

  /**
   * Creates the {@link JCommander} instance.
   *
   * Note that this method has been modified to *not* allow unknown options.
   *
   * @param methodParameter The parameters being parsed.
   * @return The {@link JCommander} instance.
   */
  private JCommander createJCommander(final MethodParameter methodParameter) {
    final Object pojo = BeanUtils.instantiateClass(methodParameter.getParameterType());
    final JCommander jCommander = new JCommander(pojo);
    jCommander.setAcceptUnknownOptions(false);
    return jCommander;
  }

  /**
   * Describe a supported parameter, so that integrated help can be generated. <p>Typical implementations will return a one element stream result, but some may
   * return several (for example if binding several words to a POJO).</p>
   *
   * @param parameter The parameter being described.
   * @return The parameter description.
   */
  @Override
  public Stream<ParameterDescription> describe(final MethodParameter parameter) {
    final JCommander jCommander = this.createJCommander(parameter);
    final Stream<com.beust.jcommander.ParameterDescription> jCommanderDescriptions = this.streamAllJCommanderDescriptions(
        jCommander);

    final BeanDescriptor constraintsForClass = this.validator.getConstraintsForClass(parameter.getParameterType());

    return jCommanderDescriptions
        .map(j -> new ParameterDescription(parameter,
            unCamelify(j.getParameterized().getType().getSimpleName()))
            .keys(Arrays.asList(j.getParameter().names()))
            .help(j.getDescription())
            .mandatoryKey(!j.equals(jCommander.getMainParameter()))
            .defaultValue(j.getParameterAnnotation().required() ? null : j.getDefault() == "" ? null : String.valueOf(j.getDefault()))
            .elementDescriptor(constraintsForClass.getConstraintsForProperty(j.getParameterized().getName())));
  }

  /**
   * Turn the given textual input into an actual object, maybe using some conversion or lookup mechanism.
   *
   * @param methodParameter The parameter being parsed.
   * @param words           The overall parse stream.
   * @return The result of parsing.
   */
  @Override
  public ValueResult resolve(final MethodParameter methodParameter, final List<String> words) {
    final JCommander jCommander = this.createJCommander(methodParameter);
    jCommander.parse(words.toArray(new String[0]));
    return new ValueResult(methodParameter, jCommander.getObjects().get(0));
  }

  /**
   * Autowired.
   *
   * @param validatorFactory The validation factory.
   */
  @Autowired(required = false)
  public void setValidatorFactory(final ValidatorFactory validatorFactory) {
    this.validator = validatorFactory.getValidator();
  }

  /**
   * Returns <em>all</em> JCommander parameter descriptions, including the "main" parameter if present.
   *
   * @param jCommander The {@link JCommander} instance.
   * @return The parameter descriptions.
   */
  private Stream<com.beust.jcommander.ParameterDescription> streamAllJCommanderDescriptions(final JCommander jCommander) {
    return Stream.concat(
        jCommander.getParameters().stream(),
        jCommander.getMainParameter() != null ? Stream.of(jCommander.getMainParameter()) : Stream.empty());
  }

  /**
   * Should return true if this resolver recognizes the given method parameter (<em>e.g.</em> it has the correct annotation or the correct type). Modified to remove
   * check on reflective access.
   *
   * @param parameter The parameter being parsed.
   * @return True if it is recognised.
   */
  @Override
  public boolean supports(final MethodParameter parameter) {
    final AtomicBoolean isSupported = new AtomicBoolean(false);
    final Class<?> parameterType = parameter.getParameterType();

    ReflectionUtils.doWithFields(parameterType, field -> {
      ReflectionUtils.makeAccessible(field);
      final boolean hasAnnotation = Arrays.stream(field.getAnnotations())
          .map(Annotation::annotationType)
          .anyMatch(JCOMMANDER_ANNOTATIONS::contains);
      isSupported.compareAndSet(false, hasAnnotation);
    });

    ReflectionUtils.doWithMethods(parameterType, method -> {
      ReflectionUtils.makeAccessible(method);
      final boolean hasAnnotation = Arrays.stream(method.getAnnotations())
          .map(Annotation::annotationType)
          .anyMatch(Parameter.class::equals);
      isSupported.compareAndSet(false, hasAnnotation);
    });

    return isSupported.get();
  }
}
