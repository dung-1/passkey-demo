package com.example.passkey_demo.service;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.passkey_demo.config.WebAuthnConfig;
import com.example.passkey_demo.entity.Challenge;
import com.example.passkey_demo.entity.Credential;
import com.example.passkey_demo.entity.User;
import com.example.passkey_demo.exception.NoCredentialException;
import com.example.passkey_demo.repository.ChallengeRepository;
import com.example.passkey_demo.repository.CredentialRepository;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AttestationConveyancePreference;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.AuthenticationRequest;
import com.webauthn4j.data.AuthenticatorAssertionResponse;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.AuthenticatorSelectionCriteria;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialParameters;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.PublicKeyCredentialRpEntity;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.PublicKeyCredentialUserEntity;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.UserVerificationRequirement;
import com.webauthn4j.data.attestation.authenticator.AAGUID;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import com.webauthn4j.server.ServerProperty;
import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.verifier.exception.VerificationException;

@Service
public class PasskeyService {

    private static final Logger logger = LoggerFactory.getLogger(PasskeyService.class);

    @Autowired
    private CredentialRepository credentialRepository;

    @Autowired
    private ChallengeRepository challengeRepository;

    @Autowired
    private WebAuthnConfig webAuthnConfig;

    @Autowired
    private WebAuthnManager webAuthnManager;

    @Value("${webauthn.rp.id:nonevadingly-nonconversant-amber.ngrok-free.dev}")
    private String rpId;

    @Value("${webauthn.origin:https://nonevadingly-nonconversant-amber.ngrok-free.dev}")
    private String origin;

    private final SecureRandom random = new SecureRandom();
    private final ObjectConverter objectConverter = new ObjectConverter();

    @Transactional
    public PublicKeyCredentialCreationOptions startRegistration(User user) {
        logger.info("Starting passkey registration for user: {}", user.getEmail());

        // Xóa TẤT CẢ challenge REGISTRATION cũ của user để đảm bảo chỉ có 1 challenge active
        // Điều này tránh race condition và challenge mismatch
        challengeRepository.deleteAllByEmailAndType(
                user.getEmail(),
                Challenge.ChallengeType.REGISTRATION
        );

        logger.debug("Deleted old registration challenges for user: {}", user.getEmail());

        // Generate WebAuthn challenge
        com.webauthn4j.data.client.challenge.Challenge webAuthnChallenge = generateChallenge();

        // Log challenge value (base64url encoded) để debug - QUAN TRỌNG để verify match
        String challengeBase64 = Base64UrlUtil.encodeToString(webAuthnChallenge.getValue());
        logger.info("Generated challenge for user {}: {}", user.getEmail(), challengeBase64);

        // Save challenge to database (raw bytes)
        Challenge dbChallenge = new Challenge(
                webAuthnChallenge.getValue(),
                user.getEmail(),
                Challenge.ChallengeType.REGISTRATION);
        challengeRepository.save(dbChallenge);
        logger.debug("Saved registration challenge (ID: {}) for user: {}",
                dbChallenge.getId(), user.getEmail());

        PublicKeyCredentialUserEntity userEntity = new PublicKeyCredentialUserEntity(
                user.getId().toString().getBytes(),
                user.getEmail(),
                user.getEmail());

        PublicKeyCredentialRpEntity rpEntity = new PublicKeyCredentialRpEntity(
                rpId,
                webAuthnConfig.getRpName());

        List<PublicKeyCredentialParameters> pubKeyCredParams = webAuthnConfig.publicKeyCredentialParameters();
        AuthenticatorSelectionCriteria authenticatorSelection = webAuthnConfig.authenticatorSelectionCriteria();

        return new PublicKeyCredentialCreationOptions(
                rpEntity,
                userEntity,
                webAuthnChallenge,
                pubKeyCredParams,
                null,
                null,
                authenticatorSelection,
                AttestationConveyancePreference.NONE,
                null);
    }

    @Transactional
    public void finishRegistration(
            PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential,
            User user) throws Exception {

        logger.info("Finishing passkey registration for user: {}", user.getEmail());

        Challenge dbChallenge = null;
        try {
            // Load challenge mới nhất từ database (ORDER BY createdAt DESC)
            // Đảm bảo lấy đúng challenge được tạo gần nhất
            dbChallenge = challengeRepository
                    .findFirstByEmailAndTypeOrderByCreatedAtDesc(
                            user.getEmail(), Challenge.ChallengeType.REGISTRATION)
                    .orElseThrow(() -> {
                        logger.error("Challenge not found for user: {}", user.getEmail());
                        return new RuntimeException("Challenge not found for user: " + user.getEmail());
                    });

            logger.debug("Found challenge (ID: {}) for user: {}", dbChallenge.getId(), user.getEmail());

            // Validate challenge expiration
            if (dbChallenge.isExpired()) {
                challengeRepository.delete(dbChallenge);
                logger.error("Challenge expired for user: {}", user.getEmail());
                throw new RuntimeException("Challenge has expired. Please try again.");
            }

            // Log challenge từ database (base64url) - QUAN TRỌNG để verify match
            String challengeFromDb = Base64UrlUtil.encodeToString(dbChallenge.getChallenge());
            logger.info("Challenge from DB for user {}: {}", user.getEmail(), challengeFromDb);

            // Convert database challenge to WebAuthn challenge
            com.webauthn4j.data.client.challenge.Challenge webAuthnChallenge = new DefaultChallenge(
                    dbChallenge.getChallenge());
            Origin originObj = new Origin(origin);

            ServerProperty serverProperty = new ServerProperty(originObj, rpId, webAuthnChallenge, null);

            // Log challenge trong ServerProperty để verify match với challenge từ DB
            String challengeInServerProperty = Base64UrlUtil.encodeToString(webAuthnChallenge.getValue());
            logger.info("Challenge in ServerProperty for user {}: {}", user.getEmail(), challengeInServerProperty);

            // Verify challenge match - 2 log trên PHẢI giống nhau tuyệt đối
            if (!challengeFromDb.equals(challengeInServerProperty)) {
                logger.error("CHALLENGE MISMATCH for user {}: DB={}, ServerProperty={}",
                        user.getEmail(), challengeFromDb, challengeInServerProperty);
                challengeRepository.delete(dbChallenge);
                throw new RuntimeException("Challenge mismatch detected");
            }

            logger.debug("Challenge match verified for user: {}", user.getEmail());

            // Create RegistrationRequest from credential
            RegistrationRequest registrationRequest = new RegistrationRequest(
                    credential.getResponse().getAttestationObject(),
                    credential.getResponse().getClientDataJSON());

            // Create RegistrationParameters
            RegistrationParameters registrationParameters = new RegistrationParameters(
                    serverProperty,
                    null,
                    false // userVerificationRequired
            );

            // Validate and parse registration
            RegistrationData registrationData;
            try {
                logger.debug("Validating registration for user: {} with challenge: {}",
                        user.getEmail(), challengeInServerProperty);
                registrationData = webAuthnManager.validate(
                        registrationRequest,
                        registrationParameters);
                logger.info("Registration validation successful for user: {}", user.getEmail());
            } catch (VerificationException e) {
                logger.error("Registration validation failed for user: {} - Error: {}",
                        user.getEmail(), e.getMessage(), e);
                logger.error("Challenge from DB: {}", challengeFromDb);
                logger.error("Challenge in ServerProperty: {}", challengeInServerProperty);
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after validation failure for user: {}",
                        dbChallenge.getId(), user.getEmail());
                throw new RuntimeException("Registration validation failed: " + e.getMessage(), e);
            }

            // Get credential public key - get the raw bytes from attestation object
            // The public key is stored as CBOR-encoded COSEKey in the attestation object
            byte[] credentialPublicKey;
            try {
                // Get the attested credential data which contains the COSEKey
                var attestedCredentialData = registrationData.getAttestationObject()
                        .getAuthenticatorData()
                        .getAttestedCredentialData();

                // Serialize the COSEKey to bytes using ObjectConverter
                credentialPublicKey = objectConverter.getCborConverter().writeValueAsBytes(
                        attestedCredentialData.getCOSEKey());
            } catch (Exception e) {
                logger.error("Failed to serialize COSEKey for user: {}", user.getEmail(), e);
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after COSEKey serialization failure for user: {}",
                        dbChallenge.getId(), user.getEmail());
                throw new RuntimeException("Failed to process credential public key", e);
            }

            // Save to DB
            try {
                Credential dbCredential = new Credential();
                dbCredential.setUser(user);
                dbCredential.setCredentialId(registrationData.getAttestationObject()
                        .getAuthenticatorData()
                        .getAttestedCredentialData()
                        .getCredentialId());
                dbCredential.setPublicKey(credentialPublicKey); // Save actual public key
                dbCredential.setSignatureCount(registrationData.getAttestationObject()
                        .getAuthenticatorData()
                        .getSignCount());
                credentialRepository.save(dbCredential);
                logger.info("Credential saved successfully for user: {}", user.getEmail());
            } catch (Exception e) {
                logger.error("Failed to save credential for user: {}", user.getEmail(), e);
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after credential save failure for user: {}",
                        dbChallenge.getId(), user.getEmail());
                throw new RuntimeException("Failed to save credential: " + e.getMessage(), e);
            }

            // Delete challenge ONLY after successful completion of all steps
            // This prevents challenge reuse and ensures it's only deleted on success
            challengeRepository.delete(dbChallenge);
            logger.debug("Deleted challenge (ID: {}) after successful registration completion for user: {}",
                    dbChallenge.getId(), user.getEmail());

        } catch (RuntimeException e) {
            // Re-throw RuntimeException (challenge already handled in specific cases)
            throw e;
        } catch (Exception e) {
            logger.error("Unexpected error during registration for user: {}", user.getEmail(), e);
            // Ensure challenge is deleted on any unexpected error
            if (dbChallenge != null) {
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after unexpected error for user: {}",
                        dbChallenge.getId(), user.getEmail());
            }
            throw new RuntimeException("Registration failed: " + e.getMessage(), e);
        }
    }

    @Transactional
    public PublicKeyCredentialRequestOptions startAuthentication(User user) throws NoCredentialException {
        logger.info("Starting passkey authentication for user: {}", user.getEmail());

        // Check credentials FIRST before generating challenge
        List<Credential> userCredentials = credentialRepository.findByUserId(user.getId());
        if (userCredentials.isEmpty()) {
            logger.warn("No credentials found for user: {}", user.getEmail());
            throw new NoCredentialException("No passkey registered for this user");
        }

        // Delete old AUTHENTICATION challenges to prevent reuse and race conditions
        challengeRepository.deleteAllByEmailAndType(
                user.getEmail(),
                Challenge.ChallengeType.AUTHENTICATION
        );
        logger.debug("Deleted old authentication challenges for user: {}", user.getEmail());

        // Generate WebAuthn challenge
        com.webauthn4j.data.client.challenge.Challenge webAuthnChallenge = generateChallenge();

        // Log challenge value (base64url encoded) for debugging
        String challengeBase64 = Base64UrlUtil.encodeToString(webAuthnChallenge.getValue());
        logger.info("Generated challenge for user {}: {}", user.getEmail(), challengeBase64);

        // Save challenge to database (raw bytes)
        Challenge dbChallenge = new Challenge(
                webAuthnChallenge.getValue(),
                user.getEmail(),
                Challenge.ChallengeType.AUTHENTICATION);
        challengeRepository.save(dbChallenge);
        logger.debug("Saved authentication challenge (ID: {}) for user: {}",
                dbChallenge.getId(), user.getEmail());

        List<PublicKeyCredentialDescriptor> allowCredentials = userCredentials.stream()
                .map(cred -> new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                cred.getCredentialId(),
                null))
                .collect(Collectors.toList());

        return new PublicKeyCredentialRequestOptions(
                webAuthnChallenge,
                null,
                rpId,
                allowCredentials,
                UserVerificationRequirement.PREFERRED,
                null);
    }

    @Transactional
    public AuthenticationResult finishAuthentication(
            PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential,
            User user) {

        Challenge dbChallenge = null;
        try {
            logger.info("Finishing passkey authentication for user: {}", user.getEmail());

            // 1. Load challenge - use findFirstByEmailAndTypeOrderByCreatedAtDesc to get latest
            dbChallenge = challengeRepository
                    .findFirstByEmailAndTypeOrderByCreatedAtDesc(
                            user.getEmail(), Challenge.ChallengeType.AUTHENTICATION)
                    .orElse(null);

            if (dbChallenge == null) {
                logger.error("Challenge not found for user: {}", user.getEmail());
                return AuthenticationResult.CHALLENGE_NOT_FOUND;
            }

            logger.debug("Found challenge (ID: {}) for user: {}", dbChallenge.getId(), user.getEmail());

            // Validate challenge expiration
            if (dbChallenge.isExpired()) {
                challengeRepository.delete(dbChallenge);
                logger.error("Challenge expired for user: {}", user.getEmail());
                return AuthenticationResult.CHALLENGE_EXPIRED;
            }

            // Log challenge from database (base64url) for debugging
            String challengeFromDb = Base64UrlUtil.encodeToString(dbChallenge.getChallenge());
            logger.info("Challenge from DB for user {}: {}", user.getEmail(), challengeFromDb);

            // 2. Build ServerProperty
            com.webauthn4j.data.client.challenge.Challenge webAuthnChallenge
                    = new DefaultChallenge(dbChallenge.getChallenge());

            Origin originObj = new Origin(origin);

            ServerProperty serverProperty = new ServerProperty(
                    originObj,
                    rpId,
                    webAuthnChallenge,
                    null
            );

            // Log challenge in ServerProperty to verify match with challenge from DB
            String challengeInServerProperty = Base64UrlUtil.encodeToString(webAuthnChallenge.getValue());
            logger.info("Challenge in ServerProperty for user {}: {}", user.getEmail(), challengeInServerProperty);

            // Verify challenge match - must be identical
            if (!challengeFromDb.equals(challengeInServerProperty)) {
                logger.error("CHALLENGE MISMATCH for user {}: DB={}, ServerProperty={}",
                        user.getEmail(), challengeFromDb, challengeInServerProperty);
                challengeRepository.delete(dbChallenge);
                return AuthenticationResult.VERIFICATION_FAILED;
            }

            logger.debug("Challenge match verified for user: {}", user.getEmail());

            // 3. Decode credentialId
            byte[] credentialId = Base64UrlUtil.decode(credential.getId());

            Credential dbCredential = credentialRepository
                    .findByUserId(user.getId())
                    .stream()
                    .filter(c -> Arrays.equals(c.getCredentialId(), credentialId))
                    .findFirst()
                    .orElse(null);

            if (dbCredential == null) {
                logger.error("Credential not found for user: {}", user.getEmail());
                challengeRepository.delete(dbChallenge);
                return AuthenticationResult.CREDENTIAL_NOT_FOUND;
            }

            if (dbCredential.getPublicKey() == null) {
                logger.error("Public key not found for credential of user: {}", user.getEmail());
                challengeRepository.delete(dbChallenge);
                return AuthenticationResult.CREDENTIAL_NOT_FOUND;
            }

            // 4. Create AuthenticationRequest
            AuthenticationRequest authenticationRequest = new AuthenticationRequest(
                    credentialId,
                    credential.getResponse().getUserHandle(),
                    credential.getResponse().getAuthenticatorData(),
                    credential.getResponse().getClientDataJSON(),
                    credential.getResponse().getSignature()
            );

            // 5. Deserialize COSEKey
            COSEKey coseKey;
            try {
                coseKey = objectConverter.getCborConverter()
                        .readValue(dbCredential.getPublicKey(), COSEKey.class);
            } catch (Exception e) {
                logger.error("Failed to deserialize COSEKey for user: {}", user.getEmail(), e);
                challengeRepository.delete(dbChallenge);
                return AuthenticationResult.VERIFICATION_FAILED;
            }

            // 6. Build Authenticator
            AttestedCredentialData attestedCredentialData
                    = new AttestedCredentialData(
                            AAGUID.ZERO,
                            credentialId,
                            coseKey
                    );

            Authenticator authenticator = new AuthenticatorImpl(
                    attestedCredentialData,
                    null,
                    dbCredential.getSignatureCount()
            );

            // 7. AuthenticationParameters
            AuthenticationParameters authenticationParameters
                    = new AuthenticationParameters(
                            serverProperty,
                            authenticator,
                            false,
                            false
                    );

            // 8. Validate
            logger.debug("Validating authentication for user: {} with challenge: {}",
                    user.getEmail(), challengeInServerProperty);
            AuthenticationData authenticationData = webAuthnManager.validate(
                    authenticationRequest,
                    authenticationParameters
            );
            logger.info("Authentication validation successful for user: {}", user.getEmail());

            // 9. Update signCount
            dbCredential.setSignatureCount(
                    authenticationData.getAuthenticatorData().getSignCount()
            );
            credentialRepository.save(dbCredential);

            // 10. Delete challenge ONLY after successful verification
            challengeRepository.delete(dbChallenge);
            logger.debug("Deleted challenge (ID: {}) after successful validation for user: {}",
                    dbChallenge.getId(), user.getEmail());

            logger.info("Authentication success for user: {}", user.getEmail());
            return AuthenticationResult.SUCCESS;

        } catch (VerificationException e) {
            logger.error("Authentication verification failed for user: {} - Error: {}",
                    user.getEmail(), e.getMessage(), e);
            if (dbChallenge != null) {
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after verification failure for user: {}",
                        dbChallenge.getId(), user.getEmail());
            }
            return AuthenticationResult.VERIFICATION_FAILED;
        } catch (Exception e) {
            logger.error("Unexpected error during authentication for user: {}", user.getEmail(), e);
            if (dbChallenge != null) {
                challengeRepository.delete(dbChallenge);
                logger.debug("Deleted challenge (ID: {}) after unexpected error for user: {}",
                        dbChallenge.getId(), user.getEmail());
            }
            return AuthenticationResult.VERIFICATION_FAILED;
        }
    }

    private com.webauthn4j.data.client.challenge.Challenge generateChallenge() {
        byte[] challengeBytes = new byte[32];
        random.nextBytes(challengeBytes);
        return new DefaultChallenge(challengeBytes);
    }
}
