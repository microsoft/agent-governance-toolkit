// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;

/** The engine's own validation of a manifest and its Rego modules, reached through the binding. */
@EnabledIf("com.microsoft.agentgovernance.acs.NativeAvailability#available")
class ArtifactValidatorTest {

    @Test
    void aManifestThatDeclaresRegoWithoutAModuleIsNotValidAndSaysSo() {
        ArtifactValidator.Result result = ArtifactValidator.validate(NativeRuntimeTest.MANIFEST, Map.of());

        assertFalse(result.valid());
        assertEquals("rego_missing", result.diagnostics().get(0).code());
        assertEquals("rego", result.diagnostics().get(0).component());
    }

    @Test
    void yamlThatDoesNotParseIsADiagnosticNotAnException() {
        ArtifactValidator.Result result = ArtifactValidator.validate("this: [broken\n", Map.of());

        assertFalse(result.valid());
        assertEquals("manifest_parse_error", result.diagnostics().get(0).code());
    }

    @Test
    void aManifestThatBreaksTheSchemaIsADiagnostic() {
        ArtifactValidator.Result result = ArtifactValidator.validate("agent_control_specification_version: 0.4.0-alpha.1\n", Map.of());

        assertFalse(result.valid());
        assertEquals("manifest_schema_error", result.diagnostics().get(0).code());
    }

    @Test
    void aNulInAnyInputIsRefusedAsADiagnosticBeforeItReachesTheEngine() {
        assertEquals("manifest_parse_error", ArtifactValidator.validate("a\0b", Map.of()).diagnostics().get(0).code());
        assertEquals("rego_parse_error", ArtifactValidator.validate(NativeRuntimeTest.MANIFEST, Map.of("p.rego", "package a\0b")).diagnostics().get(0).code());
        assertEquals("opa_execution_error", ArtifactValidator.validate(NativeRuntimeTest.MANIFEST, Map.of("p.rego", "package acs"), "op\0a").diagnostics().get(0).code());
    }

    @Test
    void aValidManifestWithItsRegoModuleIsValidWhenOpaIsAvailable() {
        ArtifactValidator.Result result = ArtifactValidator.validate(NativeRuntimeTest.MANIFEST,
                Map.of("policy.rego", "package acs\n\nverdict := {\"decision\": \"allow\"}\n"));
        Assumptions.assumeFalse(result.diagnostics().stream().anyMatch(d -> "opa_execution_error".equals(d.code())),
                "OPA is not installed (set ACS_OPA_PATH or put opa on the PATH)");

        assertTrue(result.valid(), result.toString());
        assertNotNull(result.diagnostics());
    }
}
