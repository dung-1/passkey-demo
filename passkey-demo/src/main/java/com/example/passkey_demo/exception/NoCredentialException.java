package com.example.passkey_demo.exception;

/**
 * Exception thrown when authentication is attempted but no credentials exist for the user.
 * This is a domain exception that should be handled gracefully by the controller.
 */
public class NoCredentialException extends Exception {
    
    public NoCredentialException(String message) {
        super(message);
    }
    
    public NoCredentialException(String message, Throwable cause) {
        super(message, cause);
    }
}
