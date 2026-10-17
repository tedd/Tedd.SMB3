document.querySelectorAll('[data-copy-target]').forEach((button) => {
  button.addEventListener('click', async () => {
    const target = document.getElementById(button.dataset.copyTarget);
    const status = document.getElementById('copy-status');
    if (!target) return;
    try {
      await navigator.clipboard.writeText(target.textContent);
      button.textContent = 'Copied';
      status.textContent = 'Code copied to clipboard.';
      setTimeout(() => { button.textContent = 'Copy'; }, 1800);
    } catch {
      status.textContent = 'Clipboard unavailable. Select the code and copy it manually.';
      const range = document.createRange();
      range.selectNodeContents(target);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
    }
  });
});
