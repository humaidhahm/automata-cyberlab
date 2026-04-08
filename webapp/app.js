const inputField = document.getElementById("inputField");
const traceOutput = document.getElementById("traceOutput");
const statusBadge = document.getElementById("statusBadge");
const logPanel = document.getElementById("logPanel");
const diagramPanel = document.getElementById("diagramPanel");
const diagramHost = document.getElementById("diagramHost");
const diagramCaption = document.getElementById("diagramCaption");

const modal = document.getElementById("ruleModal");
const closeModalBtn = document.getElementById("closeModalBtn");
const ruleTitle = document.getElementById("ruleTitle");
const ruleBody = document.getElementById("ruleBody");

const CRACK_GUESSES_PER_SECOND = 10_000_000_000;

const DEFAULT_TRACE = [
    "Ready.",
    "Pick any checker to evaluate the current input.",
    "Open a DFA diagram only when you need it.",
];

const SQLI_SIGNATURES = [
    ["SQL comment", "--"],
    ["Statement chaining", ";"],
    ["OR always true", "or 1=1"],
    ["UNION extraction", "union select"],
    ["DROP TABLE", "drop table"],
    ["EXEC command", "xp_cmdshell"],
    ["Tautology quote", "' or '"],
    ["Tautology quote", '" or "'],
];

const XSS_SIGNATURES = [
    ["Script tag", "<script"],
    ["Encoded script tag", "%3cscript"],
    ["Javascript URI", "javascript:"],
    ["Event handler", "onerror="],
    ["Event handler", "onload="],
    ["DOM cookie access", "document.cookie"],
    ["Alert payload", "alert("],
];

const RULES = {
    email: {
        title: "Validate Email Rules",
        text: "- Local part starts with a letter or digit\n- Local part may contain letters, digits, and '.'\n- Must include '@' after local part\n- Domain part uses letters and one '.' before TLD\n- TLD uses letters only",
    },
    phone: {
        title: "Validate Phone Rules",
        text: "- Exactly 10 characters\n- Every character must be a digit (0-9)",
    },
    password: {
        title: "Validate Password Rules",
        text: "- Length must be at least 8\n- At least one uppercase letter\n- At least one lowercase letter\n- At least one digit\n\nThis checker also shows an estimated brute-force crack time.",
    },
    ipv4: {
        title: "Validate IPv4 Rules",
        text: "- Format must be A.B.C.D\n- Exactly 4 octets\n- Each octet is numeric only\n- Each octet value must be 0 to 255\n- Leading zeros are not allowed (except single 0)",
    },
    sqli: {
        title: "SQL Injection Detector Rules",
        text: "- Normalizes case and spacing\n- Looks for signatures such as '--', 'or 1=1', 'union select', and 'drop table'\n- Flags odd number of single quotes\n- ALERT means indicators were found",
    },
    xss: {
        title: "XSS Detector Rules",
        text: "- URL-decodes payload before scanning\n- Looks for '<script', 'javascript:', event handlers, and script-like payloads\n- ALERT means indicators were found",
    },
};

function setTrace(lines) {
    traceOutput.textContent = `${lines.join("\n")}\n`;
}

function setStatus(message, kind = "neutral") {
    statusBadge.textContent = message;
    statusBadge.className = `status ${kind}`;
}

function openLogPanel() {
    logPanel.classList.remove("hidden-section");
}

function closeLogPanel() {
    logPanel.classList.add("hidden-section");
}

function openDiagramPanel() {
    // Dedicated diagram zone is always visible in the layout.
}

function isDiagramFullscreen() {
    return (
        document.fullscreenElement === diagramPanel
        || document.webkitFullscreenElement === diagramPanel
    );
}

function requestDiagramFullscreen() {
    if (isDiagramFullscreen()) {
        return;
    }

    const requestFullscreen =
        diagramPanel.requestFullscreen
        || diagramPanel.webkitRequestFullscreen
        || diagramPanel.msRequestFullscreen;

    if (!requestFullscreen) {
        return;
    }

    const maybePromise = requestFullscreen.call(diagramPanel);
    if (maybePromise && typeof maybePromise.catch === "function") {
        maybePromise.catch(() => {});
    }
}

function closeDiagramPanel() {
    diagramCaption.textContent = "Open a DFA to render it here.";
    diagramHost.innerHTML = "";
}

function clearAll() {
    inputField.value = "";
    setTrace(DEFAULT_TRACE);
    setStatus("Ready", "neutral");
    closeLogPanel();
    closeDiagramPanel();
}

function safeDecode(text) {
    try {
        return decodeURIComponent(text);
    } catch {
        return text;
    }
}

function formatDurationFromLog10Seconds(log10Seconds) {
    if (log10Seconds < 0) {
        return "less than 1 second";
    }

    const units = [
        ["second", 0],
        ["minute", Math.log10(60)],
        ["hour", Math.log10(3600)],
        ["day", Math.log10(86400)],
        ["year", Math.log10(31557600)],
    ];

    let unitName = "second";
    let unitLog = 0;
    for (const [name, threshold] of units) {
        if (log10Seconds >= threshold) {
            unitName = name;
            unitLog = threshold;
        }
    }

    const valueLog = log10Seconds - unitLog;
    let valueText;
    if (valueLog <= 6) {
        const value = 10 ** valueLog;
        if (value >= 100) {
            valueText = value.toLocaleString(undefined, { maximumFractionDigits: 0 });
        } else if (value >= 10) {
            valueText = value.toFixed(1);
        } else {
            valueText = value.toFixed(2);
        }
    } else {
        valueText = `10^${valueLog.toFixed(2)}`;
    }

    const plural = valueText === "1" ? "" : "s";
    return `${valueText} ${unitName}${plural}`;
}

function estimatePasswordCrackTime(password) {
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasDigit = /\d/.test(password);
    const hasSymbol = /[^A-Za-z0-9]/.test(password);

    let poolSize = 0;
    const categories = [];

    if (hasLower) {
        poolSize += 26;
        categories.push("lowercase");
    }
    if (hasUpper) {
        poolSize += 26;
        categories.push("uppercase");
    }
    if (hasDigit) {
        poolSize += 10;
        categories.push("digits");
    }
    if (hasSymbol) {
        poolSize += 33;
        categories.push("symbols");
    }

    if (poolSize === 0) {
        return {
            summary: "Estimated crack time: not available",
            details: ["Input has no usable characters."],
        };
    }

    const entropyBits = password.length * Math.log2(poolSize);
    const log10Seconds =
        (entropyBits - 1 - Math.log2(CRACK_GUESSES_PER_SECOND)) / Math.log2(10);

    const details = [
        `Assumed attacker speed: ${CRACK_GUESSES_PER_SECOND.toLocaleString()} guesses/second`,
        `Character pool size: ${poolSize} (${categories.join(", ")})`,
        `Estimated entropy: ${entropyBits.toFixed(1)} bits`,
        "Model: pure brute-force search (real-world cracking can be faster or slower).",
    ];

    return {
        summary: `Estimated crack time: about ${formatDurationFromLog10Seconds(log10Seconds)}`,
        details,
    };
}

function validateEmail(email) {
    const trace = [];
    let state = "q0";

    for (const ch of email) {
        if (state === "q0") {
            if (/^[A-Za-z0-9]$/.test(ch)) {
                trace.push(`q0 -- ${ch} --> q1`);
                state = "q1";
            } else {
                trace.push(`q0 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid local part start."];
            }
        } else if (state === "q1") {
            if (/^[A-Za-z0-9.]$/.test(ch)) {
                trace.push(`q1 -- ${ch} --> q1`);
            } else if (ch === "@") {
                trace.push("q1 -- @ --> q2");
                state = "q2";
            } else {
                trace.push(`q1 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid local part character."];
            }
        } else if (state === "q2") {
            if (/^[A-Za-z]$/.test(ch)) {
                trace.push(`q2 -- ${ch} --> q3`);
                state = "q3";
            } else {
                trace.push(`q2 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid domain start."];
            }
        } else if (state === "q3") {
            if (/^[A-Za-z]$/.test(ch)) {
                trace.push(`q3 -- ${ch} --> q3`);
            } else if (ch === ".") {
                trace.push("q3 -- . --> q4");
                state = "q4";
            } else {
                trace.push(`q3 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid domain character."];
            }
        } else if (state === "q4") {
            if (/^[A-Za-z]$/.test(ch)) {
                trace.push(`q4 -- ${ch} --> q5`);
                state = "q5";
            } else {
                trace.push(`q4 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid TLD start."];
            }
        } else if (state === "q5") {
            if (/^[A-Za-z]$/.test(ch)) {
                trace.push(`q5 -- ${ch} --> q5`);
            } else {
                trace.push(`q5 -- ${ch} --> reject`);
                return [false, trace, "Rejected: invalid TLD character."];
            }
        }
    }

    if (state === "q5") {
        return [true, trace, "Accepted: valid email string."];
    }
    return [false, trace, "Rejected: incomplete email format."];
}

function validatePhone(phone) {
    const trace = [];
    let state = 0;

    for (const ch of phone) {
        if (/^\d$/.test(ch) && state < 10) {
            trace.push(`q${state} -- ${ch} --> q${state + 1}`);
            state += 1;
        } else {
            trace.push(`q${state} -- ${ch} --> reject`);
            return [false, trace, "Rejected: phone must contain exactly 10 digits."];
        }
    }

    if (state === 10) {
        return [true, trace, "Accepted: valid 10-digit phone number."];
    }
    return [false, trace, "Rejected: phone must contain exactly 10 digits."];
}

function validatePassword(password) {
    const trace = [];
    let hasUpper = false;
    let hasLower = false;
    let hasDigit = false;

    for (const ch of password) {
        if (/[A-Z]/.test(ch)) {
            hasUpper = true;
            trace.push(`Read ${ch}: uppercase`);
        } else if (/[a-z]/.test(ch)) {
            hasLower = true;
            trace.push(`Read ${ch}: lowercase`);
        } else if (/\d/.test(ch)) {
            hasDigit = true;
            trace.push(`Read ${ch}: digit`);
        } else {
            trace.push(`Read ${ch}: special character`);
        }
    }

    trace.push("");
    trace.push(`Length >= 8: ${password.length >= 8 ? "yes" : "no"}`);
    trace.push(`Contains uppercase: ${hasUpper ? "yes" : "no"}`);
    trace.push(`Contains lowercase: ${hasLower ? "yes" : "no"}`);
    trace.push(`Contains digit: ${hasDigit ? "yes" : "no"}`);

    const ok = password.length >= 8 && hasUpper && hasLower && hasDigit;
    if (ok) {
        return [true, trace, "Accepted: password matches all conditions."];
    }
    return [false, trace, "Rejected: password does not meet all conditions."];
}

function validateIpv4(ipAddress) {
    const trace = [];
    const octets = ipAddress.split(".");

    if (octets.length !== 4) {
        trace.push("q0 -- invalid-octet-count --> reject");
        return [false, trace, "Rejected: IPv4 address must have 4 octets."];
    }

    for (let i = 0; i < octets.length; i += 1) {
        const octet = octets[i];
        const source = `q${i}`;
        const target = `q${i + 1}`;

        if (!octet) {
            trace.push(`${source} -- empty-octet --> reject`);
            return [false, trace, "Rejected: empty IPv4 octet is not allowed."];
        }

        if (!/^\d+$/.test(octet)) {
            trace.push(`${source} -- ${octet} --> reject`);
            return [false, trace, "Rejected: IPv4 octets must be numeric."];
        }

        if (octet.length > 1 && octet.startsWith("0")) {
            trace.push(`${source} -- ${octet} --> reject`);
            return [false, trace, "Rejected: leading zeros are not allowed in IPv4 octets."];
        }

        const value = Number.parseInt(octet, 10);
        if (value < 0 || value > 255) {
            trace.push(`${source} -- ${octet} --> reject`);
            return [false, trace, "Rejected: each IPv4 octet must be in range 0-255."];
        }

        trace.push(`${source} -- ${octet} --> ${target}`);
    }

    return [true, trace, "Accepted: valid IPv4 address."];
}

function detectSqliPattern(payload) {
    const trace = [];
    const normalized = payload.toLowerCase().replace(/\s+/g, " ").trim();

    trace.push("q0 -- normalize-input --> q1");

    const hits = [];
    for (const [ruleName, signature] of SQLI_SIGNATURES) {
        if (normalized.includes(signature)) {
            hits.push(`${ruleName}: ${signature}`);
            trace.push(`q1 -- signature(${signature}) --> q_alert`);
        }
    }

    const quoteCount = (payload.match(/'/g) || []).length;
    if (quoteCount % 2 === 1) {
        hits.push("Unbalanced single quote");
        trace.push("q1 -- odd single quote count --> q_alert");
    }

    if (hits.length > 0) {
        trace.push("");
        trace.push("Indicators detected:");
        for (const hit of hits) {
            trace.push(`- ${hit}`);
        }
        return [false, trace, "Alert: potential SQL injection signature detected."];
    }

    trace.push("q1 -- no-signature --> q_safe");
    return [true, trace, "Safe: no obvious SQL injection signature detected."];
}

function detectXssPattern(payload) {
    const trace = [];
    const decoded = safeDecode(safeDecode(payload));
    const normalized = decoded.toLowerCase().replace(/\s+/g, " ").trim();

    trace.push("q0 -- decode-and-normalize --> q1");

    const hits = [];
    for (const [ruleName, signature] of XSS_SIGNATURES) {
        if (normalized.includes(signature)) {
            hits.push(`${ruleName}: ${signature}`);
            trace.push(`q1 -- signature(${signature}) --> q_alert`);
        }
    }

    if (hits.length > 0) {
        trace.push("");
        trace.push("Indicators detected:");
        for (const hit of hits) {
            trace.push(`- ${hit}`);
        }
        return [false, trace, "Alert: potential XSS payload signature detected."];
    }

    trace.push("q1 -- no-signature --> q_safe");
    return [true, trace, "Safe: no obvious XSS signature detected."];
}

function runChecker(kind) {
    const rawInput = inputField.value;
    const value = kind === "password" ? rawInput : rawInput.trim();

    if (!value) {
        setTrace(["Input is empty. Enter a value first."]);
        setStatus("Validation failed: input is empty.", "alert");
        openLogPanel();
        return;
    }

    let result;
    if (kind === "email") {
        result = validateEmail(value);
    } else if (kind === "phone") {
        result = validatePhone(value);
    } else if (kind === "password") {
        result = validatePassword(value);
    } else if (kind === "ipv4") {
        result = validateIpv4(value);
    } else if (kind === "sqli") {
        result = detectSqliPattern(value);
    } else if (kind === "xss") {
        result = detectXssPattern(value);
    } else {
        return;
    }

    const [ok, trace, summary] = result;
    const lines = [...trace, "", summary];

    if (kind === "password") {
        const estimate = estimatePasswordCrackTime(value);
        lines.push("", estimate.summary, ...estimate.details);
    }

    setTrace(lines);
    setStatus(summary, ok ? "ok" : "alert");
    openLogPanel();
}

function openRule(ruleKey) {
    const rule = RULES[ruleKey];
    if (!rule) {
        return;
    }
    ruleTitle.textContent = rule.title;
    ruleBody.textContent = rule.text;
    modal.classList.remove("hidden");
}

function closeRuleModal() {
    modal.classList.add("hidden");
}

function stateNode(x, y, label, final = false) {
    const outer = `<circle cx="${x}" cy="${y}" r="28" fill="#5ed7cb"></circle>`;
    const inner = final
        ? `<circle cx="${x}" cy="${y}" r="10" fill="#0b2a33"></circle>`
        : "";
    const text = `<text x="${x}" y="${y + 4}" text-anchor="middle" font-family="Space Grotesk" font-size="13" font-weight="700" fill="#042127">${label}</text>`;
    return `${outer}${inner}${text}`;
}

function edge(x1, y1, x2, y2, label) {
    const lx = (x1 + x2) / 2;
    const ly = (y1 + y2) / 2 - 14;
    return [
        `<line x1="${x1}" y1="${y1}" x2="${x2}" y2="${y2}" stroke="#294f8d" stroke-width="2" marker-end="url(#arrow)"></line>`,
        `<text x="${lx}" y="${ly}" text-anchor="middle" font-family="Space Grotesk" font-size="11" fill="#344b69">${label}</text>`,
    ].join("");
}

function loop(x, y, label) {
    const path = `<path d="M ${x - 16} ${y - 36} C ${x - 42} ${y - 78}, ${x + 42} ${y - 78}, ${x + 16} ${y - 36}" fill="none" stroke="#294f8d" stroke-width="2" marker-end="url(#arrow)"></path>`;
    const text = `<text x="${x}" y="${y - 84}" text-anchor="middle" font-family="Space Grotesk" font-size="11" fill="#344b69">${label}</text>`;
    return `${path}${text}`;
}

function svgShell(width, height, content) {
    return `
<svg viewBox="0 0 ${width} ${height}" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="DFA diagram">
  <defs>
    <marker id="arrow" markerWidth="10" markerHeight="8" refX="8" refY="4" orient="auto">
      <path d="M0,0 L10,4 L0,8 z" fill="#294f8d"></path>
    </marker>
  </defs>
  ${content}
</svg>`;
}

function renderEmailDiagram() {
    const y = 140;
    const xs = [78, 205, 332, 459, 586, 713];
    const parts = [];

    parts.push(edge(24, y, 58, y, "start"));
    parts.push(stateNode(xs[0], y, "q0"));
    parts.push(stateNode(xs[1], y, "q1"));
    parts.push(stateNode(xs[2], y, "q2"));
    parts.push(stateNode(xs[3], y, "q3"));
    parts.push(stateNode(xs[4], y, "q4"));
    parts.push(stateNode(xs[5], y, "q5", true));

    parts.push(edge(xs[0] + 26, y, xs[1] - 26, y, "alnum"));
    parts.push(edge(xs[1] + 26, y, xs[2] - 26, y, "@"));
    parts.push(edge(xs[2] + 26, y, xs[3] - 26, y, "alpha"));
    parts.push(edge(xs[3] + 26, y, xs[4] - 26, y, "."));
    parts.push(edge(xs[4] + 26, y, xs[5] - 26, y, "alpha"));

    parts.push(loop(xs[1], y, "alnum/."));
    parts.push(loop(xs[3], y, "alpha"));
    parts.push(loop(xs[5], y, "alpha"));

    diagramCaption.textContent = "Email DFA";
    diagramHost.innerHTML = svgShell(790, 300, parts.join(""));
}

function renderPhoneDiagram() {
    const y = 140;
    const step = 86;
    const startX = 72;
    const parts = [];

    parts.push(edge(24, y, 58, y, "start"));

    for (let i = 0; i <= 10; i += 1) {
        const x = startX + (i * step);
        parts.push(stateNode(x, y, `q${i}`, i === 10));
        if (i < 10) {
            parts.push(edge(x + 26, y, x + step - 26, y, "digit"));
        }
    }

    diagramCaption.textContent = "Phone DFA";
    diagramHost.innerHTML = svgShell(1010, 300, parts.join(""));
}

function renderIpv4Diagram() {
    const y = 140;
    const xs = [78, 220, 362, 504, 646];
    const parts = [];

    parts.push(edge(24, y, 58, y, "start"));
    parts.push(stateNode(xs[0], y, "q0"));
    parts.push(stateNode(xs[1], y, "q1"));
    parts.push(stateNode(xs[2], y, "q2"));
    parts.push(stateNode(xs[3], y, "q3"));
    parts.push(stateNode(xs[4], y, "q4", true));

    parts.push(edge(xs[0] + 26, y, xs[1] - 26, y, "octet(0-255)"));
    parts.push(edge(xs[1] + 26, y, xs[2] - 26, y, ". + octet"));
    parts.push(edge(xs[2] + 26, y, xs[3] - 26, y, ". + octet"));
    parts.push(edge(xs[3] + 26, y, xs[4] - 26, y, ". + octet"));

    diagramCaption.textContent = "IPv4 DFA";
    diagramHost.innerHTML = svgShell(730, 300, parts.join(""));
}

function renderDiagram(kind) {
    if (kind === "email") {
        renderEmailDiagram();
    } else if (kind === "phone") {
        renderPhoneDiagram();
    } else if (kind === "ipv4") {
        renderIpv4Diagram();
    } else {
        return;
    }

    openDiagramPanel();
}

for (const btn of document.querySelectorAll(".checker-btn")) {
    btn.addEventListener("click", () => runChecker(btn.dataset.checker));
}

for (const btn of document.querySelectorAll(".info-btn")) {
    btn.addEventListener("click", () => openRule(btn.dataset.rule));
}

for (const btn of document.querySelectorAll(".diagram-btn")) {
    btn.addEventListener("click", () => renderDiagram(btn.dataset.diagram));
}

diagramHost.addEventListener("click", (event) => {
    if (!(event.target instanceof Element)) {
        return;
    }

    if (!event.target.closest("svg")) {
        return;
    }

    requestDiagramFullscreen();
});

closeModalBtn.addEventListener("click", closeRuleModal);

modal.addEventListener("click", (event) => {
    if (event.target === modal) {
        closeRuleModal();
    }
});

document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        closeRuleModal();
    }
});

clearAll();
