
const messageInput = document.getElementById("messageInput");
const checkButton = document.getElementById("checkButton");
const resultPanel = document.getElementById("resultPanel");
const charCount = document.getElementById("charCount");

function escapeHTML(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;"
  })[character]);
}

if (messageInput && charCount) {
  messageInput.addEventListener("input", () => {
    charCount.textContent = `${messageInput.value.length} / 10000`;
  });
}

function clearMessage() {
  if (messageInput) messageInput.value = "";
  if (charCount) charCount.textContent = "0 / 10000";
  if (resultPanel) {
    resultPanel.innerHTML = `
      <div class="result-placeholder">
        <div class="placeholder-icon">🛡️</div>
        <h3>Your safety report will appear here</h3>
        <p>Paste a message and scan it to see the warning signs.</p>
      </div>`;
  }
}

function showError(message) {
  resultPanel.innerHTML = `
    <div class="scan-result">
      <h3>⚠️ Unable to complete scan</h3>
      <p>${escapeHTML(message)}</p>
      <p class="small-note">Check that the Flask server is running, then try again.</p>
    </div>`;
}

async function checkScam() {
  const message = messageInput?.value.trim();

  if (!message) {
    showError("Please enter a message before scanning.");
    messageInput?.focus();
    return;
  }

  checkButton.disabled = true;
  checkButton.textContent = "Scanning…";
  resultPanel.innerHTML = `
    <div class="result-placeholder">
      <div class="placeholder-icon">🔎</div>
      <h3>Checking your message…</h3>
      <p>Looking for common scam warning signs.</p>
    </div>`;

  try {
    const response = await fetch("/api/check-scam", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error || data.message || "The server rejected the request.");
    }

    renderScanResult(data);
    loadHistory();
  } catch (error) {
    showError(
      error.message?.includes("Failed to fetch")
        ? "Cannot connect to the server. Open the website through your Flask localhost address and make sure app.py is running."
        : error.message || "Something went wrong."
    );
  } finally {
    checkButton.disabled = false;
    checkButton.textContent = "Scan Message";
  }
}

function renderScanResult(data) {
  const level = String(data.level || data.risk || "Unknown").toLowerCase();
  const score = Math.max(0, Math.min(100, Number(data.score) || 0));

  let riskClass = "risk-medium";
  let icon = "⚠️";

  if (level.includes("high") || level.includes("critical")) {
    riskClass = "risk-high";
    icon = "🚨";
  } else if (level.includes("low") || level.includes("safe")) {
    riskClass = "risk-low";
    icon = "✅";
  }

  const categories = Array.isArray(data.categories) ? data.categories : [];
  const reasons = Array.isArray(data.reasons) ? data.reasons : [];
  const advice = Array.isArray(data.advice)
    ? data.advice
    : data.advice ? [data.advice] : [];

  resultPanel.innerHTML = `
    <div class="scan-result">
      <span class="risk-badge ${riskClass}">${icon} ${escapeHTML(data.level || data.risk || "Result available")}</span>
      <h3>${escapeHTML(data.title || "Message analysis complete")}</h3>
      <p>${escapeHTML(data.message || "Review the findings below before taking action.")}</p>

      <div class="score-card">
        <div class="score-heading">
          <span>Risk indicator</span>
          <strong>${score}/100</strong>
        </div>
        <div class="score-track">
          <div class="score-fill" style="width:${score}%"></div>
        </div>
        <p class="small-note">This is an indicative score from the prototype's rule-based checks, not a guarantee.</p>
      </div>

      ${categories.length ? `
        <h4>Detected categories</h4>
        <div class="category-list">
          ${categories.map(item => `<span class="category-chip">${escapeHTML(item)}</span>`).join("")}
        </div>` : ""}

      ${reasons.length ? `
        <h4>Warning signs</h4>
        <ul class="result-list">${reasons.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>` : `
        <h4>What this means</h4>
        <p>No specific warning reason was returned. That does not prove the message is safe.</p>`}

      ${advice.length ? `
        <h4>Recommended actions</h4>
        <ul class="result-list advice-list">${advice.map(item => `<li>${escapeHTML(item)}</li>`).join("")}</ul>` : ""}

      <div class="result-actions">
        <button class="secondary-button" type="button" onclick="speakText(document.getElementById('resultPanel').innerText)">🔊 Read report aloud</button>
        <button class="secondary-button" type="button" onclick="openHelper()">💬 Need help?</button>
      </div>

      <p class="small-note">${escapeHTML(data.disclaimer || "Automated checks can miss scams. Verify through official channels.")}</p>
    </div>`;
}

async function loadHistory() {
  const historyList = document.getElementById("historyList");
  if (!historyList) return;

  historyList.innerHTML = "<p>Loading scan history…</p>";

  try {
    const response = await fetch("/api/scam-history");
    if (!response.ok) throw new Error("History request failed.");

    const data = await response.json();
    const records = Array.isArray(data.history)
      ? data.history
      : Array.isArray(data.records) ? data.records : [];

    const stats = data.stats || {};

    document.getElementById("totalScans").textContent =
      stats.total ?? data.total ?? records.length;

    document.getElementById("highRiskScans").textContent =
      stats.high ?? stats.high_risk ?? records.filter(item =>
        String(item.risk_level || item.level || "").toLowerCase().includes("high")
      ).length;

    document.getElementById("otherScans").textContent =
      Math.max(0, Number(stats.total ?? data.total ?? records.length) -
        Number(stats.high ?? stats.high_risk ?? records.filter(item =>
          String(item.risk_level || item.level || "").toLowerCase().includes("high")
        ).length));

    if (!records.length) {
      historyList.innerHTML = "<p>No scan history yet. Scan a message to see activity here.</p>";
      return;
    }

    historyList.innerHTML = `
      <table class="history-table">
        <thead><tr>
          <th>Time</th><th>Risk level</th><th>Score</th><th>Categories</th>
        </tr></thead>
        <tbody>
          ${records.map(item => {
            const risk = item.risk_level || item.level || "Unknown";
            const normalized = String(risk).toLowerCase();
            const badge = normalized.includes("high") ? "risk-high"
              : normalized.includes("low") ? "risk-low" : "risk-medium";

            let categories = item.categories || [];
            if (typeof categories === "string") {
              try { categories = JSON.parse(categories); }
              catch { categories = [categories]; }
            }

            return `<tr>
              <td>${escapeHTML(item.timestamp || item.created_at || "—")}</td>
              <td><span class="risk-badge ${badge}">${escapeHTML(risk)}</span></td>
              <td>${escapeHTML(item.score ?? "—")}</td>
              <td>${escapeHTML(Array.isArray(categories) ? categories.join(", ") : categories)}</td>
            </tr>`;
          }).join("")}
        </tbody>
      </table>`;
  } catch {
    historyList.innerHTML = `
      <p>Could not load scan history. Make sure app.py is running and the API endpoint is available.</p>`;
  }
}

async function clearHistory() {
  const confirmed = window.confirm(
    "Clear all saved scan history from this prototype?"
  );
  if (!confirmed) return;

  try {
    const response = await fetch("/api/scam-history", { method: "DELETE" });
    const data = await response.json();

    if (!response.ok) throw new Error(data.error || "Could not clear history.");

    await loadHistory();
    alert("Scan history cleared.");
  } catch (error) {
    alert(error.message || "Could not clear scan history.");
  }
}

/* One unified Need Help assistant */

function openHelper() {
  const panel = document.getElementById("helperPanel");
  if (!panel) return;

  panel.hidden = false;
  document.getElementById("helperInput")?.focus();
}

function closeHelper() {
  const panel = document.getElementById("helperPanel");
  if (panel) panel.hidden = true;
}

function addHelperMessage(text, sender = "bot") {
  const messages = document.getElementById("helperMessages");
  if (!messages) return;

  const paragraph = document.createElement("p");
  paragraph.className = sender === "user" ? "user-message" : "bot-message";
  paragraph.textContent = text;
  messages.appendChild(paragraph);
  messages.scrollTop = messages.scrollHeight;
}

function askHelper(question) {
  openHelper();
  addHelperMessage(question, "user");

  const text = question.toLowerCase();
  let reply;

  if (text.includes("shared my otp") || text.includes("shared my pin") ||
      text.includes("shared otp") || text.includes("shared pin")) {
    reply = "Act immediately: contact your bank or payment provider using its official contact details and ask them to secure your account. Change compromised credentials through official channels. If money was lost in India, call 1930 promptly and report it at cybercrime.gov.in. Never share another OTP or PIN.";
  } else if (text.includes("lost money") || text.includes("already paid") ||
             text.includes("money was stolen") || text.includes("scammed")) {
    reply = "Contact your bank or payment provider immediately and report the transaction. In India, call 1930 as soon as possible and file a report at https://cybercrime.gov.in/. Keep transaction IDs and screenshots. Do not pay anyone who promises to recover your money for a fee.";
  } else if (text.includes("upi") || text.includes("payment request") ||
             text.includes("qr code")) {
    reply = "Check the recipient name and amount before approving a payment. Never enter your UPI PIN to receive money or share it with another person. Reject unexpected collect requests and verify payment status inside your official payment app.";
  } else if (text.includes("otp") || text.includes("pin") ||
             text.includes("password") || text.includes("bank account")) {
    reply = "Never share an OTP, UPI PIN, password, or card security code. A caller claiming to be bank support should not need these secrets. End suspicious calls and contact your bank through its official app or website.";
  } else if (text.includes("link") || text.includes("message") ||
             text.includes("scam")) {
    reply = "Do not click suspicious links, install unknown apps, or rush because of threats or prizes. Scan the message with the Scam Scanner, then verify the sender through an official channel. A low-risk scan does not guarantee safety.";
  } else if (text.includes("safe") || text.includes("tips")) {
    reply = "Stay safe: use official apps, keep your device updated, lock your screen, verify recipients and amounts, never share PINs or OTPs, avoid unknown links, and enable bank transaction alerts.";
  } else {
    reply = "I can help with common digital payment safety questions, but this prototype uses predefined guidance rather than a live AI service. Tell me whether your concern is a UPI request, suspicious link, OTP/PIN, or money already lost. For urgent financial fraud in India, call 1930 and contact your bank.";
  }

  addHelperMessage(reply, "bot");
  speakText(reply);
}

const helperForm = document.getElementById("helperForm");
if (helperForm) {
  helperForm.addEventListener("submit", event => {
    event.preventDefault();
    const input = document.getElementById("helperInput");
    const question = input.value.trim();

    if (!question) return;
    input.value = "";
    askHelper(question);
  });
}

/* Voice input */

function startVoiceInput() {
  const status = document.getElementById("voiceStatus");
  const SpeechRecognition =
    window.SpeechRecognition || window.webkitSpeechRecognition;

  if (!SpeechRecognition) {
    status.textContent =
      "Voice input is not supported in this browser. Try a recent version of Chrome.";
    return;
  }

  const recognition = new SpeechRecognition();
  recognition.lang = "en-IN";
  recognition.interimResults = false;
  recognition.maxAlternatives = 1;

  status.textContent = "Listening… Speak now.";

  recognition.onresult = event => {
    const spoken = event.results[0][0].transcript;
    messageInput.value = `${messageInput.value} ${spoken}`.trim();
    messageInput.dispatchEvent(new Event("input"));
    status.textContent = "Voice input added. Review it before scanning.";
  };

  recognition.onerror = () => {
    status.textContent = "Could not capture speech. Check microphone permission and try again.";
  };

  recognition.onend = () => {
    if (status.textContent === "Listening… Speak now.") {
      status.textContent = "Voice input ended.";
    }
  };

  recognition.start();
}

function speakText(text) {
  if (!("speechSynthesis" in window)) return;

  window.speechSynthesis.cancel();
  const utterance = new SpeechSynthesisUtterance(String(text).slice(0, 4000));
  utterance.lang = "en-IN";
  utterance.rate = 0.95;
  window.speechSynthesis.speak(utterance);
}

/* Add visual styles for the dynamic scan report */

const dynamicStyles = document.createElement("style");
dynamicStyles.textContent = `
  .scan-result h3 {
    color: #152b49;
    font-family: 'Manrope', sans-serif;
    margin: 14px 0 8px;
  }
  .scan-result h4 {
    margin: 21px 0 9px;
    color: #25344b;
    font-size: 13px;
  }
  .scan-result > p { color: #68778c; font-size: 13px; }
  .score-card {
    margin-top: 20px;
    padding: 16px;
    border: 1px solid #e5eaf2;
    border-radius: 13px;
    background: #fff;
  }
  .score-heading {
    display: flex;
    justify-content: space-between;
    gap: 12px;
    font-size: 12px;
  }
  .score-heading strong { color: #152b49; font-size: 18px; }
  .score-track {
    height: 8px;
    margin-top: 12px;
    overflow: hidden;
    background: #e9edf5;
    border-radius: 20px;
  }
  .score-fill {
    height: 100%;
    background: #3569e8;
    border-radius: 20px;
    transition: width .4s ease;
  }
  .category-list, .result-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }
  .category-chip {
    padding: 6px 10px;
    color: #2452c7;
    background: #edf2ff;
    border-radius: 20px;
    font-size: 11px;
  }
  .result-list {
    padding-left: 20px;
    color: #53637a;
    font-size: 12px;
  }
  .result-list li { margin: 8px 0; }
  .advice-list li::marker { color: #16845b; }
  .result-actions { margin-top: 18px; }
  #checkButton:disabled { opacity: .65; cursor: wait; }
`;
document.head.appendChild(dynamicStyles);

document.addEventListener("DOMContentLoaded", () => {
  loadHistory();
});
