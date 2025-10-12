// Select all tab buttons and their corresponding content panels
const tabs = document.querySelectorAll(".tab");
const panels = document.querySelectorAll(".tab-panel");

// Add click listener to each tab
tabs.forEach(tab => {
  tab.addEventListener("click", () => {
    // Reset all tabs and hide all panels
    tabs.forEach(t => t.setAttribute("aria-selected", "false"));
    panels.forEach(p => p.classList.add("hidden"));

    // Mark the clicked tab as active
    tab.setAttribute("aria-selected", "true");

    // Show the content panel linked to this tab
    document.getElementById(tab.dataset.tab + "-panel").classList.remove("hidden");
  });
});

// Drag and drop functionality for file upload
document.querySelectorAll(".drop-zone").forEach(zone => {
  const input = zone.querySelector("input");     // File input inside drop zone
  const form = zone.closest("form");             // Parent form for auto-submit

  // Click zone to open file picker
  zone.addEventListener("click", () => input.click());

  // Highlight drop zone when dragging file over it
  zone.addEventListener("dragover", e => {
    e.preventDefault();
    zone.style.background = "rgba(126,162,255,0.1)";
  });

  // Remove highlight when drag leaves the zone
  zone.addEventListener("dragleave", () => {
    zone.style.background = "";
  });

  // Handle dropped file
  zone.addEventListener("drop", e => {
    e.preventDefault();
    input.files = e.dataTransfer.files; // Assign dropped files to the input
    zone.style.background = "";

    if (input.files.length > 0) {
      alert(`File selected: ${input.files[0].name}`);

      // Automatically submit the form if it's an .eml file
      if (form && input.files[0].name.endsWith('.eml')) {
        form.submit();
      }
    }
  });

  // Handle file selection via file picker
  input.addEventListener("change", () => {
    if (input.files.length > 0) {
      // Automatically submit the form if it's an .eml file
      if (form && input.files[0].name.endsWith('.eml')) {
        form.submit();
      }
    }
  });
});