package com.example.passkey_demo.config;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Value; // <- Add this import
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.data.AuthenticatorAttachment;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.ResidentKeyRequirement;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;

@Configuration
public class WebAuthnConfig {

    @Value("${webauthn.rp.id:nonevadingly-nonconversant-amber.ngrok-free.dev}")
    private String rpId;

    @Value("${webauthn.rp.name:Passkey Demo}")
    private String rpName;

    @Value("${webauthn.origin:https://nonevadingly-nonconversant-amber.ngrok-free.dev}")
    private String origin;

    public String getRpName() {
        return rpName;
    }

    @Bean
    public List<PublicKeyCredentialParameters> publicKeyCredentialParameters() {
        // Fixed: Use new PublicKeyCredentialParameters(...) and Collections.singletonList
        PublicKeyCredentialParameters param = new PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256 // <- Already imported correctly
        );

        return Collections.singletonList(param); // Or List.of(param) if using Java 9+
    }

    @Bean
    public AuthenticatorSelectionCriteria authenticatorSelectionCriteria() {
        return new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM,
                ResidentKeyRequirement.REQUIRED,
                UserVerificationRequirement.REQUIRED);
    }

    @Bean
    public WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }
}
