package com.example.qrgen.oid4vp;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

public record DirectPostRequest(
        String state,
        @JsonProperty("vp_token")
        Object vpToken,
        @JsonProperty("presentation_submission")
        Map<String, Object> presentationSubmission
) {
}
