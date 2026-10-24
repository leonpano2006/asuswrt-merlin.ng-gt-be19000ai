/* GPL-2.0-or-later. Read-only validation through the installed libsensors API.
 * Target build: cc -std=c11 -O2 -Wall -Wextra -Werror -fno-lto
 *                  validate-libsensors.c -lsensors -lm -o validate-libsensors
 */
#include <math.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sensors/sensors.h>

_Static_assert(SENSORS_FEATURE_TEMP == 2, "unexpected temperature ABI");
_Static_assert(SENSORS_FEATURE_FREQ == 25, "libsensors frequency ABI required");
_Static_assert(SENSORS_SUBFEATURE_FREQ_INPUT == 6400, "unexpected frequency ABI");

static void printString(const char* text) {
   const unsigned char* cursor = (const unsigned char*)(text ? text : "");
   putchar('"');
   for (; *cursor; ++cursor) {
      if (*cursor == '"' || *cursor == '\\')
         printf("\\%c", *cursor);
      else if (*cursor < 0x20)
         printf("\\u%04x", (unsigned int)*cursor);
      else
         putchar(*cursor);
   }
   putchar('"');
}

int main(void) {
   int status = sensors_init(NULL);
   if (status != 0) {
      fprintf(stderr, "sensors_init failed: %d\n", status);
      return EXIT_FAILURE;
   }

   unsigned int chipCount = 0;
   unsigned int temperatureCount = 0;
   unsigned int frequencyCount = 0;
   unsigned int errors = 0;
   int chipIndex = 0;
   const sensors_chip_name* chip;
   while ((chip = sensors_get_detected_chips(NULL, &chipIndex)) != NULL) {
      if (!chip->prefix || strcmp(chip->prefix, "bcm4916") != 0)
         continue;
      ++chipCount;
      char chipName[256] = {0};
      if (sensors_snprintf_chip_name(chipName, sizeof(chipName), chip) < 0) {
         ++errors;
         continue;
      }

      int featureIndex = 0;
      const sensors_feature* feature;
      while ((feature = sensors_get_features(chip, &featureIndex)) != NULL) {
         bool temperature = feature->type == SENSORS_FEATURE_TEMP;
         bool frequency = feature->type == SENSORS_FEATURE_FREQ;
         if (!temperature && !frequency)
            continue;
         sensors_subfeature_type inputType = temperature ? SENSORS_SUBFEATURE_TEMP_INPUT :
                                                          SENSORS_SUBFEATURE_FREQ_INPUT;
         const sensors_subfeature* input = sensors_get_subfeature(chip, feature, inputType);
         double value = NAN;
         status = input ? sensors_get_value(chip, input->number, &value) : -1;
         /* Negative Celsius is valid. Frequency must be strictly positive. */
         bool valid = status == 0 && isfinite(value) && (temperature || value > 0.0);
         char* label = sensors_get_label(chip, feature);

         fputs("{\"chip\":", stdout);
         printString(chipName);
         fputs(",\"path\":", stdout);
         printString(chip->path);
         fputs(",\"feature\":", stdout);
         printString(feature->name);
         printf(",\"feature_type\":%d,\"label\":", (int)feature->type);
         printString(label);
         printf(",\"status\":%d,\"unit\":\"%s\",\"value\":", status,
                temperature ? "C" : "Hz");
         if (valid)
            printf("%.6f", value);
         else
            fputs("null", stdout);
         printf(",\"valid\":%s}\n", valid ? "true" : "false");
         free(label);

         if (!valid)
            ++errors;
         else if (temperature)
            ++temperatureCount;
         else
            ++frequencyCount;
      }
   }

   bool success = chipCount == 1 && temperatureCount == 1 && frequencyCount == 1 && errors == 0;
   fputs("{\"libsensors_version\":", stdout);
   printString(libsensors_version);
   printf(",\"chips\":%u,\"temperatures\":%u,\"frequencies\":%u,\"errors\":%u,\"success\":%s}\n",
          chipCount, temperatureCount, frequencyCount, errors, success ? "true" : "false");
   sensors_cleanup();
   return success ? EXIT_SUCCESS : EXIT_FAILURE;
}
