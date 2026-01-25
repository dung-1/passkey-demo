package com.example.passkey_demo.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.example.passkey_demo.entity.User;
import com.example.passkey_demo.exception.NoCredentialException;
import com.example.passkey_demo.repository.UserRepository;
import com.example.passkey_demo.service.AuthenticationResult;
import com.example.passkey_demo.service.JwtService;
import com.example.passkey_demo.service.PasskeyService;
import com.webauthn4j.data.AuthenticatorAssertionResponse;
import com.webauthn4j.data.AuthenticatorAttestationResponse;
import com.webauthn4j.data.PublicKeyCredential;
import com.webauthn4j.data.PublicKeyCredentialCreationOptions;
import com.webauthn4j.data.PublicKeyCredentialRequestOptions;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientOutput;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;

@RestController
public class PasskeyController {

    @Autowired
    private PasskeyService passkeyService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/register-passkey/start")
    public PublicKeyCredentialCreationOptions startRegistration() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return passkeyService.startRegistration(user);
    }

    @PostMapping("/register-passkey/finish")
    public ResponseEntity<String> finishRegistration(@RequestBody PublicKeyCredential<AuthenticatorAttestationResponse, RegistrationExtensionClientOutput> credential) {
        try {
            User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            passkeyService.finishRegistration(credential, user);
            return ResponseEntity.ok("Passkey registered successfully");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Registration failed: " + e.getMessage());
        }
    }

    @GetMapping("/login-passkey/start")
    public ResponseEntity<?> startAuthentication(@RequestParam String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            PublicKeyCredentialRequestOptions options = passkeyService.startAuthentication(user);
            return ResponseEntity.ok(options);
        } catch (NoCredentialException e) {
            return ResponseEntity.status(404).body("No passkey registered for this user. Please register a passkey first.");
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Failed to start authentication: " + e.getMessage());
        }
    }

    @PostMapping("/login-passkey/finish")
    public ResponseEntity<String> finishAuthentication(
            @RequestBody PublicKeyCredential<AuthenticatorAssertionResponse, AuthenticationExtensionClientOutput> credential,
            @RequestParam String email) {
        try {
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
            AuthenticationResult result = passkeyService.finishAuthentication(credential, user);
            
            switch (result) {
                case SUCCESS:
                    String token = jwtService.generateToken(user);
                    return ResponseEntity.ok(token);
                case NEED_REGISTER_PASSKEY:
                    return ResponseEntity.status(404).body("No passkey registered for this user. Please register a passkey first.");
                case CHALLENGE_NOT_FOUND:
                    return ResponseEntity.badRequest().body("Authentication challenge not found. Please start authentication again.");
                case CHALLENGE_EXPIRED:
                    return ResponseEntity.badRequest().body("Authentication challenge has expired. Please start authentication again.");
                case CREDENTIAL_NOT_FOUND:
                    return ResponseEntity.badRequest().body("Credential not found. Please register a new passkey.");
                case VERIFICATION_FAILED:
                default:
                    return ResponseEntity.badRequest().body("Authentication verification failed. Please try again.");
            }
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Authentication failed: " + e.getMessage());
        }
    }
}
