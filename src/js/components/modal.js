// Modal confirmation and dialog utility
export function showConfirmModal({
  title,
  description,
  confirmText = "Confirm",
  confirmDestructive = false,
  cancelText = "Cancel",
  onConfirm = () => {},
  onCancel = () => {}
}) {
  const modal = document.getElementById("confirm-modal");
  if (!modal) return;

  const titleEl = modal.querySelector(".modal-title");
  const descEl = modal.querySelector(".modal-description");
  const confirmBtn = modal.querySelector("#modal-confirm-btn");
  const cancelBtn = modal.querySelector("#modal-cancel-btn");

  if (titleEl) titleEl.textContent = title;
  if (descEl) descEl.textContent = description;
  if (confirmBtn) {
    confirmBtn.textContent = confirmText;
    confirmBtn.className = confirmDestructive ? "btn btn-destructive" : "btn btn-primary";
  }
  if (cancelBtn) cancelBtn.textContent = cancelText;

  modal.classList.add("active");

  const cleanup = () => {
    modal.classList.remove("active");
    confirmBtn.onclick = null;
    cancelBtn.onclick = null;
  };

  confirmBtn.onclick = () => {
    cleanup();
    onConfirm();
  };

  cancelBtn.onclick = () => {
    cleanup();
    onCancel();
  };
}

export function closeModal() {
  const modal = document.getElementById("confirm-modal");
  if (modal) modal.classList.remove("active");
}
