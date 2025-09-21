// Tab switching
const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".tab-panel");

tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    tabs.forEach(t => t.setAttribute("aria-selected","false"));
    panels.forEach(p => p.classList.add("hidden"));

    tab.setAttribute("aria-selected","true");
    document.getElementById(tab.dataset.tab + "-panel").classList.remove("hidden");
  });
});

// Drag & Drop - **UPDATED SECTION**
document.querySelectorAll(".drop-zone").forEach(zone => {
  const input = zone.querySelector("input");
  const form = zone.closest("form");
  
  zone.addEventListener("click", () => input.click());
  
  zone.addEventListener("dragover", e => {
    e.preventDefault();
    zone.style.background = "rgba(126,162,255,0.1)";
  });
  zone.addEventListener("dragleave", () => {
    zone.style.background = "";
  });
  zone.addEventListener("drop", e => {
    e.preventDefault();
    input.files = e.dataTransfer.files;
    zone.style.background = "";
    if (input.files.length > 0) {
      alert(`File selected: ${input.files[0].name}`);
      // Auto-submit for .eml files
      if (form && input.files[0].name.endsWith('.eml')) {
        form.submit();
      }
    }
  });
  
  input.addEventListener("change", () => {
    if (input.files.length > 0) {
      alert(`File selected: ${input.files[0].name}`);
      // Auto-submit for .eml files
      if (form && input.files[0].name.endsWith('.eml')) {
        form.submit();
      }
    }
  });
});