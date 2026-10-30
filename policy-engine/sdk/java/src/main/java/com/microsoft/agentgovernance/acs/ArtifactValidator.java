// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package com.microsoft.agentgovernance.acs;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/** Validates an ACS manifest and its Rego modules with the engine, before anything runs. */
public final class ArtifactValidator {

    private static final ObjectMapper JSON = new ObjectMapper();

    private ArtifactValidator() {
    }

    /**
     * One problem found in an artifact.
     *
     * @param path   where in the artifact, when known
     * @param line   1-based, when known
     * @param column 1-based, when known
     */
    public record Diagnostic(String component, String code, String message, String source, String path, Long line, Long column, String snippet) {
    }

    /** @param valid true when no diagnostic is an error */
    public record Result(boolean valid, List<Diagnostic> diagnostics) {
        public Result {
            diagnostics = List.copyOf(diagnostics);
        }
    }

    /**
     * @param manifest    the manifest as YAML
     * @param regoModules source name to Rego text; may be empty
     * @param opaPath     the OPA executable, or null to look it up as the engine does ({@code ACS_OPA_PATH}, then the {@code PATH})
     * @throws AcsException if the engine itself fails (a malformed manifest is a result, not an exception)
     */
    public static Result validate(String manifest, Map<String, String> regoModules, String opaPath) {
        Objects.requireNonNull(manifest, "manifest");
        Map<String, String> modules = regoModules == null ? Map.of() : regoModules;
        if (manifest.indexOf('\0') >= 0) {
            return invalid("manifest", "manifest_parse_error", "Manifest input contains an embedded null character.", "manifest");
        }
        if (!modules.isEmpty() && opaPath != null && opaPath.indexOf('\0') >= 0) {
            return invalid("rego", "opa_execution_error", "OPA path contains an embedded null character.", "opa");
        }
        for (Map.Entry<String, String> module : modules.entrySet()) {
            if (module.getValue().indexOf('\0') >= 0) {
                return invalid("rego", "rego_parse_error", "Rego module " + module.getKey() + " contains an embedded null character.", module.getKey());
            }
        }
        String modulesJson;
        try {
            modulesJson = JSON.writeValueAsString(modules);
        } catch (com.fasterxml.jackson.core.JsonProcessingException e) {
            throw new IllegalArgumentException("The Rego modules cannot be written as JSON: " + e.getMessage(), e);
        }
        String json = NativeApi.get().validate(manifest, modulesJson, opaPath);
        try {
            return read(JSON.readTree(json));
        } catch (java.io.IOException | RuntimeException e) {
            throw new AcsException("The engine returned a validation result that cannot be read: " + e.getMessage(), e);
        }
    }

    public static Result validate(String manifest, Map<String, String> regoModules) {
        return validate(manifest, regoModules, null);
    }

    private static Result invalid(String component, String code, String message, String source) {
        return new Result(false, List.of(new Diagnostic(component, code, message, source, null, null, null, null)));
    }

    private static Result read(JsonNode raw) {
        List<Diagnostic> diagnostics = new ArrayList<>();
        JsonNode list = raw.get("diagnostics");
        if (list != null && list.isArray()) {
            for (JsonNode d : list) {
                diagnostics.add(new Diagnostic(text(d, "component"), text(d, "code"), text(d, "message"), text(d, "source"), text(d, "path"),
                        number(d, "line"), number(d, "column"), text(d, "snippet")));
            }
        }
        return new Result(raw.path("valid").asBoolean(false), diagnostics);
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText();
    }

    private static Long number(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asLong();
    }
}
