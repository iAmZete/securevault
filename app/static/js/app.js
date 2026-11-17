// SecureVault client helpers. Loaded as an external file so the
// Content-Security-Policy can forbid inline scripts entirely.
// All security decisions are enforced server-side; this is UX only.
document.addEventListener("DOMContentLoaded", function () {
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        event.preventDefault();
      }
    });
  });

  // Client-side size hint (server re-validates the 10 MB limit).
  var input = document.querySelector(".sv-upload input[type=file]");
  if (input) {
    input.addEventListener("change", function () {
      var file = input.files && input.files[0];
      input.setCustomValidity(file && file.size > 10 * 1024 * 1024 ? "File exceeds the 10 MB limit." : "");
    });
  }
});
