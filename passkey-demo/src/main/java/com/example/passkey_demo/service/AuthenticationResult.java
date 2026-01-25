package com.example.passkey_demo.service;

/**
 * Domain response enum for authentication operations.
 * Provides clear, actionable results instead of generic exceptions.
 */
public enum AuthenticationResult {
    SUCCESS,
    NEED_REGISTER_PASSKEY,  // No credentials exist for user
    CHALLENGE_NOT_FOUND,
    CHALLENGE_EXPIRED,
    VERIFICATION_FAILED,
    CREDENTIAL_NOT_FOUND
}
