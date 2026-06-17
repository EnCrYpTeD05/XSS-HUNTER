const intro = document.getElementById("intro");
const app = document.getElementById("app");
const form = document.getElementById("scanForm");
const formError = document.getElementById("formError");
const startBtn = document.getElementById("startBtn");
const stateText = document.getElementById("stateText");
const stepText = document.getElementById("stepText");
const progressBar = document.getElementById("progressBar");
const logs = document.getElementById("logs");
const artifacts = document.getElementById("artifacts");
const history = document.getElementById("history");

let activeJobId = null;
let pollTimer = null;
let activeStatus = "idle";

setTimeout(() => {
  intro.classList.add("hidden");
  app.classList.remove("hidden");
  resetDashboard();
}, 7200);

function bytes(size) {
  if (!size) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const order = Math.min(Math.floor(Math.log(size) / Math.log(1024)), units.length - 1);
  return `${(size / Math.pow(1024, order)).toFixed(order ? 1 : 0)} ${units[order]}`;
}

function normalizeStatus(status) {
  const map = {
    queued: "Queued",
    running: "Running",
    waiting: "Waiting",
    paused: "Paused",
    failed: "Failed",
    stopped: "Stopped By User",
    completed: "Scan Finish",
  };
  return map[status] || "Idle";
}

function resetDashboard() {
  activeJobId = null;
  activeStatus = "idle";
  stateText.textContent = "Idle";
  stepText.textContent = "Ready for target input.";
  progressBar.style.width = "0%";
  logs.textContent = "Waiting for scan...";
  artifacts.innerHTML = `<p class="empty">Output files will appear here after each scanner step.</p>`;
  history.innerHTML = `<p class="empty">New dashboard session. Previous scans are hidden.</p>`;
  startBtn.disabled = false;
  startBtn.textContent = "Start Scan";
  startBtn.classList.remove("danger", "resume");
}

function renderJob(job) {
  activeJobId = job.id;
  activeStatus = job.status || "idle";
  stateText.textContent = normalizeStatus(job.status);
  stepText.textContent = job.message || job.step || "Ready.";
  progressBar.style.width = `${job.progress || 0}%`;
  logs.textContent = (job.logs && job.logs.length) ? job.logs.join("\n") : "Waiting for scan...";
  logs.scrollTop = logs.scrollHeight;

  if (job.artifacts && job.artifacts.length) {
    artifacts.innerHTML = job.artifacts.map((file) => `
      <div class="artifact">
        <div>
          <strong>${escapeHtml(file.name)}</strong>
          <small>${bytes(file.size)}</small>
        </div>
        <a class="btn download" href="${file.url}">Download</a>
      </div>
    `).join("");
  } else {
    artifacts.innerHTML = `<p class="empty">Output files will appear here after each scanner step.</p>`;
  }

  const busy = ["queued", "running", "waiting"].includes(job.status);
  const resumable = job.status === "stopped";
  startBtn.disabled = false;
  startBtn.textContent = busy ? "Stop Scan" : resumable ? "Resume Scan" : "Start Scan";
  startBtn.classList.toggle("danger", busy);
  startBtn.classList.toggle("resume", resumable);
}

function renderHistory(jobs) {
  if (!jobs.length) {
    history.innerHTML = `<p class="empty">No previous web runs loaded.</p>`;
    return;
  }
  history.innerHTML = jobs.map((job) => `
    <button class="history-item" data-job="${job.id}" type="button">
      <span>
        <strong>${escapeHtml(job.config.domain)}</strong>
        <small>${normalizeStatus(job.status)} - ${escapeHtml(job.step || "Queued")} - ${job.created_at}</small>
      </span>
      <small>${job.progress || 0}%</small>
    </button>
  `).join("");
  history.querySelectorAll("[data-job]").forEach((button) => {
    button.addEventListener("click", () => {
      activeJobId = button.dataset.job;
      pollJob();
      startPolling();
    });
  });
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadJobs({ selectActive = false } = {}) {
  try {
    const res = await fetch("/api/jobs");
    const data = await res.json();
    const jobs = (data.jobs || []).sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));
    const visibleJobs = selectActive ? jobs : jobs.filter((job) => job.id === activeJobId);
    renderHistory(visibleJobs);
    if (!selectActive && !activeJobId) return;
    const live = jobs.find((job) => ["queued", "running", "waiting"].includes(job.status));
    const latest = activeJobId ? jobs.find((job) => job.id === activeJobId) : live;
    if (latest) {
      activeJobId = latest.id;
      renderJob(latest);
      if (live) startPolling();
    }
  } catch (err) {
    formError.textContent = `Could not load jobs: ${err.message}`;
  }
}

async function pollJob() {
  if (!activeJobId) return;
  try {
    const res = await fetch(`/api/status/${activeJobId}`);
    const job = await res.json();
    if (!res.ok) throw new Error(job.error || "Could not load job status");
    renderJob(job);
    loadJobs({ selectActive: true });
    if (!["queued", "running", "waiting"].includes(job.status)) {
      stopPolling();
    }
  } catch (err) {
    formError.textContent = err.message;
    stopPolling();
  }
}

function startPolling() {
  stopPolling();
  pollTimer = setInterval(pollJob, 1400);
}

function stopPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = null;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  formError.textContent = "";

  if (["queued", "running", "waiting"].includes(activeStatus) && activeJobId) {
    await stopScan();
    return;
  }

  if (activeStatus === "stopped" && activeJobId) {
    await resumeScan();
    return;
  }

  startBtn.disabled = true;
  startBtn.textContent = "Starting...";

  const payload = Object.fromEntries(new FormData(form).entries());
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan could not start");
    activeJobId = data.job_id;
    logs.textContent = "Scan queued...";
    loadJobs({ selectActive: true });
    startPolling();
  } catch (err) {
    formError.textContent = err.message;
    startBtn.disabled = false;
    startBtn.textContent = "Start Scan";
  }
});

async function stopScan() {
  formError.textContent = "";
  startBtn.disabled = true;
  startBtn.textContent = "Stopping...";
  try {
    const res = await fetch(`/api/stop/${activeJobId}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan could not stop");
    activeStatus = "stopped";
    stateText.textContent = "Stopped By User";
    stepText.textContent = "Stopped by user.";
    await pollJob();
  } catch (err) {
    formError.textContent = err.message;
  } finally {
    startBtn.disabled = false;
    startBtn.textContent = "Resume Scan";
    startBtn.classList.remove("danger");
    startBtn.classList.add("resume");
    stopPolling();
    loadJobs({ selectActive: true });
  }
}

async function resumeScan() {
  formError.textContent = "";
  startBtn.disabled = true;
  startBtn.textContent = "Resuming...";
  try {
    const res = await fetch(`/api/resume/${activeJobId}`, { method: "POST" });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Scan could not resume");
    activeStatus = "queued";
    stateText.textContent = "Queued";
    stepText.textContent = "Resume queued.";
    startBtn.classList.remove("resume");
    startPolling();
  } catch (err) {
    formError.textContent = err.message;
    startBtn.disabled = false;
    startBtn.textContent = "Resume Scan";
    startBtn.classList.add("resume");
  }
}
