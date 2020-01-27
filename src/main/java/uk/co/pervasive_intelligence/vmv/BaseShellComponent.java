/*
 * Trusted and Transparent Voting Systems: Verify My Vote Demonstrator
 *
 * (c) University of Surrey 2018
 */
package uk.co.pervasive_intelligence.vmv;

import com.fasterxml.jackson.annotation.JsonView;
import com.fasterxml.jackson.databind.*;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.BeanPropertyDefinition;
import com.fasterxml.jackson.databind.util.NameTransformer;
import com.fasterxml.jackson.dataformat.csv.CsvGenerator;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import org.springframework.shell.standard.ShellComponent;

import javax.validation.ConstraintViolation;
import javax.validation.Validation;
import javax.validation.Validator;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Defines common methods for {@link ShellComponent} classes.
 *
 * @author Matthew Casey, Pervasive Intelligence Ltd
 */
public abstract class BaseShellComponent {

  /**
   * Creates the CSV mapper with appropriate options and with the view filtering.
   *
   * @param view The optional view to filter for.
   * @return The CSV mapper.
   */
  private CsvMapper getCsvMapper(final Class<?> view) {
    final ApplyViewCsvMapper csvMapper = new ApplyViewCsvMapper(view);
    csvMapper.configure(CsvGenerator.Feature.ALWAYS_QUOTE_STRINGS, true);

    return csvMapper;
  }

  /**
   * Reads the content of a CSV file and returns a list of the read objects.
   *
   * @param file  The input file.
   * @param clazz The class (or contained class) of the content.
   * @return The list of values read in.
   * @throws VMVException if the file could not be read.
   */
  public List<?> readCSV(final File file, final Class<?> clazz) throws VMVException {
    return this.readCSV(file, clazz, null);
  }

  /**
   * Reads the content of a CSV file and returns a list of the read objects. If an optional view is provided then only those properties with a view that matches are
   * read. No properties are included by default if they do not have an associated {@link JsonView}.
   *
   * @param file  The input file.
   * @param clazz The class (or contained class) of the content.
   * @param view  The optional view to filter for.
   * @return The list of values read in.
   * @throws VMVException if the file could not be read.
   */
  public List<?> readCSV(final File file, final Class<?> clazz, final Class<?> view) throws VMVException {
    try {
      // Construct the mapper and schema for the optional view and class.
      final CsvMapper csvMapper = this.getCsvMapper(view);
      final CsvSchema schema = csvMapper.schemaFor(clazz).withHeader();

      // Read the values, validating each as they are read.
      ObjectReader reader = csvMapper.readerFor(clazz).with(schema);

      if (view != null) {
        reader = reader.withView(view);
      }

      final MappingIterator<Object> iterator = reader.readValues(file);
      final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
      final List<Object> values = new ArrayList<>();

      while (iterator.hasNextValue()) {
        final Object value = iterator.nextValue();
        final Set<ConstraintViolation<Object>> valid = validator.validate(value);

        if (!valid.isEmpty()) {
          throw new VMVException("Could not validate de-serialised object: " + valid);
        }

        values.add(value);
      }

      return values;
    }
    catch (final VMVException e) {
      throw e;
    }
    catch (final Exception e) {
      throw new VMVException("Could not read CSV file " + file, e);
    }
  }

  /**
   * Writes the content as CSV to the file using the optional view. If an optional view is provided then only those properties with a view that matches are written.
   * No properties are included by default if they do not have an associated {@link JsonView}.
   *
   * @param file    The output file.
   * @param clazz   The class (or contained class) of the content.
   * @param content The content to write.
   * @param view    The optional view to filter for.
   * @throws VMVException if the file could not be written.
   */
  public void writeCSV(final File file, final Class<?> clazz, final Object content, final Class<?> view) throws VMVException {
    try {
      // Construct the mapper and schema for the optional view and class.
      final CsvMapper csvMapper = this.getCsvMapper(view);
      final CsvSchema schema = csvMapper.schemaFor(clazz).withHeader();

      // Write the values.
      ObjectWriter writer = csvMapper.writer().with(schema);

      if (view != null) {
        writer = writer.withView(view);
      }

      writer.writeValue(file, content);
    }
    catch (final Exception e) {
      throw new VMVException("Could not write CSV file " + file, e);
    }
  }

  /**
   * Writes the content as CSV to the file.
   *
   * @param file    The output file.
   * @param clazz   The class (or contained class) of the content.
   * @param content The content to write.
   * @throws VMVException if the file could not be written.
   */
  public void writeCSV(final File file, final Class<?> clazz, final Object content) throws VMVException {
    this.writeCSV(file, clazz, content, null);
  }

  /**
   * Custom {@link CsvMapper} which builds a schema based upon the available views.
   */
  public static class ApplyViewCsvMapper extends CsvMapper {

    /** The currently active view, if any. */
    private final Class<?> activeView;

    /**
     * Default constructor: no view is applied.
     */
    public ApplyViewCsvMapper() {
      this(null);
    }

    /**
     * Constructor allowing the view to be defined.
     *
     * @param activeView The currently active view. May  be null.
     */
    public ApplyViewCsvMapper(final Class<?> activeView) {
      this.activeView = activeView;
    }

    /**
     * Adds schema properties for the POJO. Modified from base class.
     *
     * @param builder      The CSV schema builder.
     * @param introspector The annotation introspector.
     * @param typed        Is field typed?
     * @param pojoType     The POJO.
     * @param unwrapper    Unwraps a field to get its name.
     */
    @Override
    protected void _addSchemaProperties(final CsvSchema.Builder builder, final AnnotationIntrospector introspector, final boolean typed, final JavaType pojoType,
                                        final NameTransformer unwrapper) {
      if (!this._nonPojoType(pojoType)) {
        final BeanDescription beanDesc = this.getSerializationConfig().introspect(pojoType);
        final Iterator i$ = beanDesc.findProperties().iterator();

        while (true) {
          while (true) {
            BeanPropertyDefinition property;

            do {
              if (!i$.hasNext()) {
                return;
              }

              property = (BeanPropertyDefinition) i$.next();
            } while (!property.couldSerialize());

            // Always assume the property is included.
            final AnnotatedMember member = property.getPrimaryMember();
            boolean include = true;

            if (member != null) {
              if (this.activeView != null) {
                // If a view is being applied, only include the property if it includes the view or is included by default.
                include = this.isEnabled(MapperFeature.DEFAULT_VIEW_INCLUSION);

                // Check for the currently active view, if available.
                final Class<?>[] views = introspector.findViews(member);

                if (views != null) {
                  // The property explicitly has views, so disable it unless one of the views matches the active view.
                  include = false;

                  for (final Class<?> view : views) {
                    include |= view.isAssignableFrom(this.activeView);
                  }
                }
              }

              NameTransformer nextUnwrapper = introspector.findUnwrappingNameTransformer(property.getPrimaryMember());
              if (nextUnwrapper != null) {
                if (unwrapper != null) {
                  nextUnwrapper = NameTransformer.chainedTransformer(unwrapper, nextUnwrapper);
                }

                final JavaType nextType = member.getType();
                this._addSchemaProperties(builder, introspector, typed, nextType, nextUnwrapper);
                continue;
              }
            }

            // Only include the property if allowed.
            if (include) {
              String name = property.getName();
              if (unwrapper != null) {
                name = unwrapper.transform(name);
              }

              if (typed && member != null) {
                builder.addColumn(name, this._determineType(member.getRawType()));
              }
              else {
                builder.addColumn(name);
              }
            }
          }
        }
      }
    }
  }
}
