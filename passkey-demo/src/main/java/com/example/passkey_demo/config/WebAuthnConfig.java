package com.example.passkey_demo.config;

import java.util.Collections;
import java.util.List;

import org.springframework.beans.factory.annotation.Value; // ← Thêm import này
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

    @Value("${webauthn.rp.id:localhost}")
    private String rpId;

    @Value("${webauthn.rp.name:Passkey Demo}")
    private String rpName;

    @Value("${webauthn.origin:http://localhost:8082}")
    private String origin;

    public String getRpName() {
        return rpName;
    }

    @Bean
    public List<PublicKeyCredentialParameters> publicKeyCredentialParameters() {
        // Sửa: Dùng new PublicKeyCredentialParameters(...) và Collections.singletonList
        PublicKeyCredentialParameters param = new PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256 // ← Đã import đúng
        );

        return Collections.singletonList(param); // Hoặc List.of(param) nếu dùng Java 9+
    }

    @Bean
    public AuthenticatorSelectionCriteria authenticatorSelectionCriteria() {
        return new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.CROSS_PLATFORM,
                ResidentKeyRequirement.PREFERRED,
                UserVerificationRequirement.PREFERRED);
    }

    @Bean
    public WebAuthnManager webAuthnManager() {
        return WebAuthnManager.createNonStrictWebAuthnManager();
    }
}