document.querySelectorAll('[data-target]').forEach(btn => {
  btn.addEventListener('click', () => {
    const input = document.getElementById(btn.dataset.target);
    if (!input) return;

    const icons = btn.querySelectorAll('i');
    const isPassword = input.type === 'password';

    input.type = isPassword ? 'text' : 'password';
    icons[0].style.display = isPassword ? 'none' : 'inline-block';
    icons[1].style.display = isPassword ? 'inline-block' : 'none';
  });
});
const adminPassword = document.getElementById("admin_password");
const toggleAdminBtn = document.getElementById("toggleAdminPassword");

if (adminPassword && toggleAdminBtn) {
  const eyeOpen = document.getElementById("eye-open");
  const eyeClosed = document.getElementById("eye-closed");

  toggleAdminBtn.addEventListener("click", () => {
    const isPassword = adminPassword.type === "password";
    adminPassword.type = isPassword ? "text" : "password";
    eyeOpen.style.display = isPassword ? "none" : "inline-block";
    eyeClosed.style.display = isPassword ? "inline-block" : "none";
  });
}
window.showToast = function (msg, type = "info") {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const t = document.createElement("div");
  t.className = `toast toast-${type}`;
  t.textContent = msg;
  container.appendChild(t);

  setTimeout(() => t.remove(), 3000);
};
const signupForm = document.getElementById("signupForm");

if (signupForm) {
  signupForm.addEventListener("submit", e => {
    const pass = document.getElementById("password")?.value;
    const confirm = document.getElementById("confirm_password")?.value;

    if (pass !== confirm) {
      e.preventDefault();
      showToast("Passwords do not match", "error");
    }
  });
}
const resetForm = document.getElementById("resetPasswordForm");

if (resetForm) {
  resetForm.addEventListener("submit", e => {
    const pass = document.getElementById("new_password")?.value;
    const confirm = document.getElementById("confirm_password")?.value;

    if (pass !== confirm) {
      e.preventDefault();
      showToast("Passwords do not match", "error");
    }
  });
}

