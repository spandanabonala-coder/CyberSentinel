
const API_BASE_URL = "https://cybersentinel-5za5.onrender.com";

let suspiciousCount = 0;
let failedLoginCount = 0;

async function checkURL() {
    const url = document.getElementById("urlInput").value.trim();
    const result = document.getElementById("result");

    if (!url) {
        result.textContent = "Please enter a URL.";
        return;
    }

    try {
        const response = await fetch(API_BASE_URL + "/check-url", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: url
        });

        const message = await response.text();
        result.textContent = message;

        if (message.includes("Suspicious")) {
            result.style.color = "red";
            suspiciousCount++;
            document.getElementById("urls").textContent = suspiciousCount;
            document.getElementById("alerts").textContent = suspiciousCount;
            addLog("Suspicious URL: " + url);
        } else {
            result.style.color = "green";
            addLog("URL checked: " + url);
        }
    } catch (error) {
        result.textContent = "C server connection failed!";
        result.style.color = "red";
    }
}

async function addFailedLogin() {
    try {
        const response = await fetch(API_BASE_URL + "/analyze-log", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: "FAILED login attempt"
        });

        const message = await response.text();
        failedLoginCount++;
        document.getElementById("logins").textContent = failedLoginCount;
        addLog(message);
    } catch (error) {
        addLog("C server connection failed!");
    }
}

function addLog(message) {
    const log = document.createElement("li");
    log.textContent = message;
    document.getElementById("logs").appendChild(log);
}

function clearLogs() {
    document.getElementById("logs").innerHTML = "";
}

async function simulateSecurityError() {
    try {
        const response = await fetch(API_BASE_URL + "/analyze-log", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: "ERROR unauthorized access detected"
        });

        const message = await response.text();

        await fetch(API_BASE_URL + "/add-alert", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: message
        });

        document.getElementById("alerts").textContent =
            Number(document.getElementById("alerts").textContent) + 1;

        addLog(message);
    } catch (error) {
        addLog("C server connection failed!");
    }
}

async function viewStackAlerts() {
    try {
        const response = await fetch(API_BASE_URL + "/alerts");
        const message = await response.text();

        if (message.includes("No alerts stored.")) {
            addLog("No alerts stored.");
            return;
        }

        addLog("Stored Stack Alerts:");
        message.trim().split("\n").forEach(alert => addLog(alert));
    } catch (error) {
        addLog("Could not retrieve Stack alerts.");
    }
}

async function addQueueLog() {
    try {
        const response = await fetch(API_BASE_URL + "/add-log", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: "Security log added from dashboard"
        });

        const message = await response.text();
        addLog(message);
    } catch (error) {
        addLog("Queue connection failed!");
    }
}

async function viewQueueLogs() {
    try {
        const response = await fetch(API_BASE_URL + "/queue-logs");
        const message = await response.text();

        if (message.includes("No security logs stored.")) {
            addLog(message);
            return;
        }

        addLog("Stored Queue Logs:");
        message.trim().split("\n").forEach(log => addLog(log));
    } catch (error) {
        addLog("Could not retrieve Queue logs.");
    }
}

async function addBSTSeverity() {
    const severity = prompt("Enter alert severity (1-10):");

    if (severity === null) return;

    if (!/^(10|[1-9])$/.test(severity.trim())) {
        alert("Enter a severity between 1 and 10.");
        return;
    }

    try {
        const response = await fetch(API_BASE_URL + "/add-severity", {
            method: "POST",
            headers: { "Content-Type": "text/plain" },
            body: severity.trim()
        });

        const message = await response.text();
        addLog(message);
    } catch (error) {
        addLog("BST connection failed!");
    }
}

async function viewBSTAlerts() {
    try {
        const response = await fetch(API_BASE_URL + "/bst-alerts");
        const message = await response.text();

        addLog("BST Alert Severities (Sorted): " + message);
    } catch (error) {
        addLog("Could not retrieve BST alerts.");
    }
}
