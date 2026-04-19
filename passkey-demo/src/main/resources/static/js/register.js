document
  .getElementById("registerForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;

    try {
      const response = await fetch("/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ email, password }),
      });

      const token = await response.text();
      if (response.ok) {
        localStorage.setItem("jwt", token);
        showSuccess("Registration successful! Redirecting...");
        setTimeout(() => {
          window.location.href = "/dashboard";
        }, 1500);
      } else {
        showError("Registration failed: " + token);
      }
    } catch (error) {
      showError("Error: " + error.message);
    }
  });

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
