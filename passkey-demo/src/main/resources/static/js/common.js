function logout() {
    localStorage.removeItem("jwt");
    window.location.href = "/";
}

function showError(message) {
    const errorDiv = document.getElementById("errorMessage");
    errorDiv.textContent = message;
    errorDiv.style.display = "block";
    setTimeout(() => {
        errorDiv.style.display = "none";
    }, 5000);
}

function showSuccess(message) {
    const successDiv = document.getElementById("successMessage");
    successDiv.textContent = message;
    successDiv.style.display = "block";
    setTimeout(() => {
        successDiv.style.display = "none";
    }, 5000);
}