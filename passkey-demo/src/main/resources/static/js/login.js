// Helper function to convert base64url to Uint8Array
function base64UrlToUint8Array(base64url) {
  // Validate input
  if (!base64url || typeof base64url !== "string") {
    throw new Error("Invalid base64url input: must be a non-empty string");
  }

  // Remove any existing padding
  base64url = base64url.replace(/=/g, "");

  // Replace URL-safe characters to standard base64
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");

  // Calculate and add correct padding (0, 1, 2, or 3)
  const paddingNeeded = (4 - (base64.length % 4)) % 4;
  base64 += "=".repeat(paddingNeeded);

  // Decode base64 to binary string
  const binaryString = atob(base64);

  // Convert to Uint8Array
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }

  return bytes;
}

// Helper function to set button loading state
function setButtonLoading(buttonId, loading) {
  const button = document.getElementById(buttonId);
  if (loading) {
    button.disabled = true;
    button.innerHTML =
      '<span class="spinner-border spinner-border-sm me-2"></span>Processing...';
  } else {
    button.disabled = false;
    button.innerHTML = "🔐 Login with Passkey/Biometric";
  }
}

// Login with password
document
  .getElementById("loginForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const submitBtn = e.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;

    try {
      submitBtn.disabled = true;
      submitBtn.innerHTML =
        '<span class="spinner-border spinner-border-sm me-2"></span>Logging in...';

      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;

      const response = await fetch("/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      const result = await response.text();
      if (response.ok) {
        localStorage.setItem("jwt", result);
        showSuccess("Login successful! Redirecting...");
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 500);
      } else {
        showError("Login failed: " + result);
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
      }
    } catch (error) {
      showError("Connection error: " + error.message);
      submitBtn.disabled = false;
      submitBtn.innerHTML = originalText;
    }
  });

// Login with passkey
document
  .getElementById("passkeyLoginBtn")
  .addEventListener("click", async function () {
    const email = document.getElementById("email").value;
    if (!email) {
      showError("Please enter email first");
      return;
    }

    // Check if WebAuthn is supported
    if (!window.PublicKeyCredential) {
      showError("Your browser does not support WebAuthn/Passkey");
      return;
    }

    setButtonLoading("passkeyLoginBtn", true);
    hideMessages();

    try {
      // Step 1: Get authentication options
      const startResponse = await fetch(
        `/login-passkey/start?email=${encodeURIComponent(email)}`,
      );

      if (!startResponse.ok) {
        const errorText = await startResponse.text();
        if (startResponse.status === 404) {
          throw new Error(
            "User not found or no passkey registered"
          );
        }
        throw new Error(errorText || "Cannot get authentication information");
      }

      const options = await startResponse.json();

      // Validate response
      if (!options.challenge) {
        throw new Error("Authentication information is invalid");
      }

      // Step 2: Call WebAuthn API
      // Handle challenge - WebAuthn4J may serialize it as an object with 'value' property
      // or as a direct Base64URL string
      let challengeBytes;
      try {
        let challengeString = null;

        // Check if challenge is an object with 'value' property (WebAuthn4J serialization)
        if (options.challenge && typeof options.challenge === "object") {
          if (options.challenge.value) {
            // WebAuthn4J serializes Challenge as { "value": "base64url_string" }
            challengeString = options.challenge.value;
          } else if (Array.isArray(options.challenge)) {
            // If it's already an array, convert directly
            challengeBytes = new Uint8Array(options.challenge);
          } else {
            throw new Error("Challenge object does not have expected format");
          }
        } else if (typeof options.challenge === "string") {
          challengeString = options.challenge;
        } else {
          throw new Error(
            `Unexpected challenge type: ${typeof options.challenge}`,
          );
        }

        // If we have a string, decode it from Base64URL
        if (challengeString !== null) {
          // Validate challenge format
          if (!challengeString || challengeString.trim() === "") {
            throw new Error("Challenge string is empty");
          }
          challengeBytes = base64UrlToUint8Array(challengeString);
        }

        // Validate we have challenge bytes
        if (!challengeBytes || challengeBytes.length === 0) {
          throw new Error("Challenge bytes are empty after decoding");
        }

        // Verify challenge length (should be 32 bytes for WebAuthn)
        if (challengeBytes.length !== 32) {
          throw new Error(
            `Invalid challenge length: ${challengeBytes.length} bytes, expected 32 bytes`,
          );
        }
      } catch (error) {
        console.error("[ERROR] Challenge decoding failed:", error);
        console.error("[ERROR] Challenge value:", options.challenge);
        throw new Error(`Failed to decode challenge: ${error.message}`);
      }

      // Handle allowCredentials - credential IDs may also be serialized as objects
      const allowCredentials = (options.allowCredentials || []).map((cred) => {
        let credId;
        try {
          let credIdString = null;

          if (cred.id && typeof cred.id === "object") {
            if (cred.id.value) {
              credIdString = cred.id.value;
            } else if (Array.isArray(cred.id)) {
              credId = new Uint8Array(cred.id);
            } else {
              throw new Error(
                "Credential ID object does not have expected format",
              );
            }
          } else if (typeof cred.id === "string") {
            credIdString = cred.id;
          } else if (Array.isArray(cred.id)) {
            credId = new Uint8Array(cred.id);
          } else {
            throw new Error(`Unexpected credential ID type: ${typeof cred.id}`);
          }

          // If we have a string, decode it from Base64URL
          if (credIdString !== null) {
            if (!credIdString || credIdString.trim() === "") {
              throw new Error("Credential ID string is empty");
            }
            credId = base64UrlToUint8Array(credIdString);
          }

          if (!credId || credId.length === 0) {
            throw new Error("Credential ID bytes are empty after decoding");
          }
        } catch (error) {
          console.error("[ERROR] Credential ID decoding failed:", error);
          throw new Error(`Failed to decode credential ID: ${error.message}`);
        }

        return {
          id: credId,
          type: cred.type || "public-key",
        };
      });

      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: challengeBytes,
          allowCredentials: allowCredentials,
          rpId: options.rpId,
          userVerification: options.userVerification || "preferred",
          timeout: 60000, // 60 seconds timeout
        },
      });

      if (!credential) {
        throw new Error("Did not receive authentication information");
      }

      // Step 3: Send credential to server
      const credentialForServer = {
        id: credential.id,
        rawId: Array.from(new Uint8Array(credential.rawId)),
        response: {
          authenticatorData: Array.from(
            new Uint8Array(credential.response.authenticatorData),
          ),
          clientDataJSON: Array.from(
            new Uint8Array(credential.response.clientDataJSON),
          ),
          signature: Array.from(new Uint8Array(credential.response.signature)),
          userHandle: credential.response.userHandle
            ? Array.from(new Uint8Array(credential.response.userHandle))
            : null,
        },
        type: credential.type,
      };

      const finishResponse = await fetch(
        `/login-passkey/finish?email=${encodeURIComponent(email)}`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify(credentialForServer),
        },
      );

      const result = await finishResponse.text();
      if (finishResponse.ok) {
        localStorage.setItem("jwt", result);
        showSuccess("Authentication successful! Redirecting...");
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 500);
      } else {
        showError("Passkey authentication failed: " + result);
        setButtonLoading("passkeyLoginBtn", false);
      }
    } catch (error) {
      let errorMessage = "Error: " + error.message;

      if (error.name === "NotAllowedError") {
        errorMessage = "User cancelled authentication or timeout occurred";
      } else if (error.name === "InvalidStateError") {
        errorMessage = "Passkey has been used or is invalid";
      } else if (error.name === "NotSupportedError") {
        errorMessage = "Browser or device does not support WebAuthn";
      } else if (error.name === "SecurityError") {
        errorMessage = "Security error: Please check domain and HTTPS";
      }

      showError(errorMessage);
      setButtonLoading("passkeyLoginBtn", false);
    }
  });

function hideMessages() {
  document.getElementById("errorMessage").style.display = "none";
  document.getElementById("successMessage").style.display = "none";
}

function showError(message) {
  const errorDiv = document.getElementById("errorMessage");
  errorDiv.textContent = message;
  errorDiv.style.display = "block";
  document.getElementById("successMessage").style.display = "none";
}

function showSuccess(message) {
  const successDiv = document.getElementById("successMessage");
  successDiv.textContent = message;
  successDiv.style.display = "block";
  document.getElementById("errorMessage").style.display = "none";
}
