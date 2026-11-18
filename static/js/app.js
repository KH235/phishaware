
"use strict";

// ========================================
// PhishAware - Main JavaScript
// ========================================

// URL Scanner elements
const form = document.querySelector("#scan-form");
const result = document.querySelector("#scan-result");
const btn = document.querySelector("#scan-btn");

// CSRF token provided by Flask in index.html
const csrfToken = document.querySelector(
    'meta[name="csrf-token"]'
)?.content;

// ========================================
// Sidebar Navigation
// ========================================

const navLinks = Array.from(
    document.querySelectorAll('.sidebar nav a[href^="#"]')
);

const sections = navLinks
    .map(link => {
        const id = link.getAttribute("href").slice(1);

        return {
            link: link,
            section: document.getElementById(id)
        };
    })
    .filter(item => item.section !== null);

let scrollLockUntil = 0;

function setActiveLink(activeLink) {
    navLinks.forEach(link => {
        const isActive = link === activeLink;

        link.classList.toggle("active", isActive);

        if (isActive) {
            link.setAttribute("aria-current", "location");
        } else {
            link.removeAttribute("aria-current");
        }
    });
}

// Highlight and scroll when clicking sidebar links
sections.forEach(item => {
    item.link.addEventListener("click", event => {
        event.preventDefault();

        setActiveLink(item.link);

        scrollLockUntil = Date.now() + 900;

        item.section.scrollIntoView({
            behavior: "smooth",
            block: "start"
        });

        history.replaceState(
            null,
            "",
            "#" + item.section.id
        );
    });
});

// Update sidebar highlight during manual scrolling
function updateSidebarOnScroll() {
    if (Date.now() < scrollLockUntil) {
        return;
    }

    const offset = 160;
    let current = sections[0];

    for (const item of sections) {
        if (item.section.getBoundingClientRect().top <= offset) {
            current = item;
        }
    }

    if (current) {
        setActiveLink(current.link);
    }
}

window.addEventListener(
    "scroll",
    updateSidebarOnScroll,
    { passive: true }
);

window.addEventListener(
    "resize",
    updateSidebarOnScroll
);

window.addEventListener(
    "load",
    updateSidebarOnScroll
);

// ========================================
// Helper Functions
// ========================================

// Safely create HTML elements containing text
function textEl(tag, text) {
    const node = document.createElement(tag);
    node.textContent = text;
    return node;
}

// Display scanner results
function displayScanResult(data, saved) {
    const title = textEl(
        "h4",
        `RISK: ${data.level}  •  ${data.score}/100`
    );

    title.style.color =
        data.level === "HIGH" ? "#ff5757" :
        data.level === "MEDIUM" ? "#f5b942" :
        "#36e5a3";

    const address = textEl("p", data.url);

    const indicators = document.createElement("ul");

    for (const indicator of data.indicators) {
        indicators.append(
            textEl("li", indicator)
        );
    }

    const disclaimer = textEl(
        "p",
        data.disclaimer || ""
    );

    const status = textEl(
        "p",
        saved
            ? "✓ Scan saved successfully to Scan History."
            : "Scan completed. Sign in to save scans to history."
    );

    status.style.color = saved
        ? "#36e5a3"
        : "#b9a6e8";

    result.replaceChildren(
        title,
        address,
        indicators,
        disclaimer,
        status
    );
}

// ========================================
// URL Scanner
// ========================================

if (form && result && btn) {
    form.addEventListener("submit", async event => {
        event.preventDefault();

        const urlInput = document.querySelector("#url");

        if (!urlInput) {
            return;
        }

        const url = urlInput.value.trim();

        result.hidden = false;
        result.replaceChildren(
            textEl("p", "Analyzing URL patterns...")
        );

        btn.disabled = true;

        try {
            // Step 1: Perform public URL risk analysis
            const scanResponse = await fetch("/api/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify({ url })
            });

            const scanData = await scanResponse.json();

            if (!scanResponse.ok) {
                throw new Error(
                    scanData.error || "URL scan failed."
                );
            }

            // Display the scan result immediately
            displayScanResult(scanData, false);

            // Step 2: Attempt to save for logged-in users
            let saveResponse;

            try {
                saveResponse = await fetch("/api/scans", {
                    method: "POST",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRFToken": csrfToken
                    },
                    body: JSON.stringify({ url }),
                    redirect: "manual"
                });
            } catch (saveError) {
                console.warn(
                    "Scan completed, but saving was unavailable.",
                    saveError
                );
                return;
            }

            // Visitors who aren't logged in cannot save
            if (
                saveResponse.type === "opaqueredirect" ||
                saveResponse.status === 0 ||
                saveResponse.status === 401 ||
                (
                    saveResponse.status >= 300 &&
                    saveResponse.status < 400
                )
            ) {
                return;
            }

            // Keep displaying the scan result if saving fails
            if (!saveResponse.ok) {
                console.warn(
                    "Scan completed, but the result was not saved."
                );

                const message = textEl(
                    "p",
                    "Scan completed, but saving failed."
                );

                message.style.color = "#ffcc44";
                result.append(message);
                return;
            }

            // Saved successfully
            const savedData = await saveResponse.json();

            displayScanResult(savedData, true);

        } catch (error) {
            result.replaceChildren(
                textEl(
                    "p",
                    error.message || "Something went wrong."
                )
            );
        } finally {
            btn.disabled = false;
        }
    });

}


// ==========================================
// MODULE 2 — THREAT SEARCH AND FILTER
// ==========================================

const threatSearchInput = document.querySelector("#threat-search");
const threatRiskFilter = document.querySelector("#threat-risk-filter");
const threatCards = document.querySelectorAll(".threat-card");
const threatSearchCount = document.querySelector("#threat-search-count");
const threatNoResults = document.querySelector("#threat-no-results");

function filterThreats() {
    const searchText = threatSearchInput.value.trim().toLowerCase();
    const selectedRisk = threatRiskFilter.value;

    let visibleCount = 0;

    threatCards.forEach((card) => {
        const cardText = card.textContent.toLowerCase();
        const cardRisk = card.dataset.risk;

        const matchesSearch = cardText.includes(searchText);
        const matchesRisk =
            selectedRisk === "ALL" || cardRisk === selectedRisk;

        const shouldShow = matchesSearch && matchesRisk;

        card.hidden = !shouldShow;

        if (shouldShow) {
            visibleCount++;
        }
    });

    threatSearchCount.textContent =
        `${visibleCount} matching threat(s)`;

    if (threatNoResults) {
        threatNoResults.hidden = visibleCount !== 0;
    }
}

if (threatSearchInput && threatRiskFilter) {
    threatSearchInput.addEventListener("input", filterThreats);
    threatRiskFilter.addEventListener("change", filterThreats);

    filterThreats();
}


// MODULE 2 — CUSTOM DELETE CONFIRMATION

const deleteDialog = document.querySelector("#threat-delete-dialog");
const cancelThreatDelete = document.querySelector("#cancel-threat-delete");
const confirmThreatDelete = document.querySelector("#confirm-threat-delete");

let selectedThreatDeleteForm = null;

if (deleteDialog && cancelThreatDelete && confirmThreatDelete) {
    document.querySelectorAll(".threat-delete-trigger").forEach((button) => {
        button.addEventListener("click", () => {
            selectedThreatDeleteForm = button.closest("form");
            deleteDialog.showModal();
        });
    });

    cancelThreatDelete.addEventListener("click", () => {
        deleteDialog.close();
    });

    confirmThreatDelete.addEventListener("click", () => {
        if (selectedThreatDeleteForm) {
            confirmThreatDelete.disabled = true;
            selectedThreatDeleteForm.requestSubmit();
        }
    });

    deleteDialog.addEventListener("close", () => {
        selectedThreatDeleteForm = null;
        confirmThreatDelete.disabled = false;
    });
}


/* MODULE 3 — COMMUNITY POST DELETE CONFIRMATION */

document.addEventListener("click", function (event) {
    const button = event.target.closest(".community-delete-trigger");

    if (!button) return;

    const dialog = document.querySelector("#community-delete-dialog");
    const form = button.closest("form");

    if (!dialog || !form) return;

    dialog.showModal();

    const cancelButton = document.querySelector("#cancel-community-delete");
    const confirmButton = document.querySelector("#confirm-community-delete");

    cancelButton.onclick = function () {
        dialog.close();
    };

    confirmButton.onclick = function () {
        form.requestSubmit();
    };
});


/* Keep scroll position after saving edits or deleting records */

(function () {
    const storageKey = "phishaware_scroll_position";

    // Restore the previous position after a form submission.
    const savedPosition = sessionStorage.getItem(storageKey);

    if (savedPosition !== null) {
        sessionStorage.removeItem(storageKey);

        const restorePosition = () => {
            window.scrollTo({
                top: Number(savedPosition),
                left: 0,
                behavior: "instant"
            });
        };

        // Prevent automatic smooth scrolling.
        document.documentElement.style.scrollBehavior = "auto";

        restorePosition();

        window.addEventListener("load", restorePosition, { once: true });
    }

    // Remember the position before submitting a form.
    document.addEventListener("submit", function (event) {
        const form = event.target;

        if (!(form instanceof HTMLFormElement)) return;

        if (form.method.toLowerCase() === "post") {
            sessionStorage.setItem(
                storageKey,
                String(window.scrollY)
            );
        }
    }, true);
})();


/* MODULE 4 — CUSTOM DELETE COMMENT DIALOG */

(function () {
    let pendingCommentDeleteForm = null;

    document.addEventListener("click", function (event) {
        const deleteButton = event.target.closest(
            ".community-comment-delete-btn"
        );

        if (!deleteButton) return;

        event.preventDefault();

        pendingCommentDeleteForm = deleteButton.closest("form");

        const dialog = document.getElementById("comment-delete-dialog");

        if (dialog) {
            dialog.showModal();
        }
    });

    document.addEventListener("click", function (event) {
        if (event.target.id === "cancel-comment-delete") {
            document.getElementById("comment-delete-dialog").close();
            pendingCommentDeleteForm = null;
        }

        if (event.target.id === "confirm-comment-delete") {
            if (!pendingCommentDeleteForm) return;

            const form = pendingCommentDeleteForm;
            pendingCommentDeleteForm = null;

            document.getElementById("comment-delete-dialog").close();

            // Preserve scroll position before submitting.
            sessionStorage.setItem(
                "phishaware_scroll_position",
                String(window.scrollY)
            );

            form.submit();
        }
    });

    document.addEventListener("close", function (event) {
        if (event.target.id === "comment-delete-dialog") {
            pendingCommentDeleteForm = null;
        }
    }, true);
})();


/* MODULE 5 — CUSTOM DELETE INCIDENT DIALOG */

(function () {
    let pendingIncidentDeleteForm = null;

    document.addEventListener("click", function (event) {
        const deleteButton = event.target.closest(".incident-delete-btn");

        if (!deleteButton) return;

        event.preventDefault();

        pendingIncidentDeleteForm = deleteButton.closest("form");

        const dialog = document.getElementById("incident-delete-dialog");

        if (dialog) {
            dialog.showModal();
        }
    });

    document.addEventListener("click", function (event) {
        if (event.target.id === "cancel-incident-delete") {
            document.getElementById("incident-delete-dialog").close();
            pendingIncidentDeleteForm = null;
        }

        if (event.target.id === "confirm-incident-delete") {
            if (!pendingIncidentDeleteForm) return;

            const form = pendingIncidentDeleteForm;
            pendingIncidentDeleteForm = null;

            document.getElementById("incident-delete-dialog").close();

            sessionStorage.setItem(
                "phishaware_scroll_position",
                String(window.scrollY)
            );

            form.submit();
        }
    });
})();


/* MODULE 6 — CUSTOM DELETE VERIFICATION DIALOG */

(function () {
    let pendingVerificationDeleteForm = null;

    document.addEventListener("click", function (event) {
        const deleteButton = event.target.closest(".verification-delete-btn");

        if (!deleteButton) return;

        event.preventDefault();

        pendingVerificationDeleteForm = deleteButton.closest("form");

        const dialog = document.getElementById("verification-delete-dialog");

        if (dialog) {
            dialog.showModal();
        }
    });

    document.addEventListener("click", function (event) {
        if (event.target.id === "cancel-verification-delete") {
            document.getElementById("verification-delete-dialog").close();
            pendingVerificationDeleteForm = null;
        }

        if (event.target.id === "confirm-verification-delete") {
            if (!pendingVerificationDeleteForm) return;

            const form = pendingVerificationDeleteForm;
            pendingVerificationDeleteForm = null;

            document.getElementById("verification-delete-dialog").close();

            sessionStorage.setItem(
                "phishaware_scroll_position",
                String(window.scrollY)
            );

            form.submit();
        }
    });

    const dialog = document.getElementById("verification-delete-dialog");

    if (dialog) {
        dialog.addEventListener("close", function () {
            pendingVerificationDeleteForm = null;
        });
    }
})();


/* MODULE 7 — DELETE LESSON CONFIRMATION */

document.addEventListener("DOMContentLoaded", function () {
    const dialog = document.getElementById("learning-delete-dialog");
    const cancelButton = document.getElementById("cancel-learning-delete");
    const confirmButton = document.getElementById("confirm-learning-delete");

    if (!dialog || !cancelButton || !confirmButton) {
        console.error("Cyber Learning delete dialog elements not found.");
        return;
    }

    let pendingForm = null;

    // Stop deletion BEFORE the form submits.
    document.addEventListener("submit", function (event) {
        const form = event.target;

        if (!form.matches(".learning-delete-form")) return;

        event.preventDefault();

        pendingForm = form;
        dialog.showModal();
    });

    cancelButton.addEventListener("click", function () {
        dialog.close();
        pendingForm = null;
    });

    confirmButton.addEventListener("click", function () {
        if (!pendingForm) return;

        const form = pendingForm;
        pendingForm = null;

        sessionStorage.setItem(
            "phishaware_scroll_position",
            String(window.scrollY)
        );

        dialog.close();
        form.submit();
    });

    dialog.addEventListener("close", function () {
        pendingForm = null;
    });
});


/* MODULE 8 — DELETE QUIZ QUESTION POPUP */

function setupQuizDeletePopup() {
    const dialog = document.getElementById("quiz-delete-dialog");
    const cancelButton = document.getElementById("cancel-quiz-delete");
    const confirmButton = document.getElementById("confirm-quiz-delete");

    if (!dialog || !cancelButton || !confirmButton) {
        console.error("Quiz delete popup elements are missing.");
        return;
    }

    let pendingForm = null;

    document.querySelectorAll(".quiz-delete-form").forEach(function (form) {
        form.addEventListener("submit", function (event) {
            event.preventDefault();

            pendingForm = form;
            dialog.showModal();
        });
    });

    cancelButton.addEventListener("click", function () {
        dialog.close();
        pendingForm = null;
    });

    confirmButton.addEventListener("click", function () {
        if (!pendingForm) return;

        const form = pendingForm;
        pendingForm = null;

        sessionStorage.setItem(
            "phishaware_scroll_position",
            String(window.scrollY)
        );

        dialog.close();
        form.submit();
    });

    dialog.addEventListener("close", function () {
        pendingForm = null;
    });
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", setupQuizDeletePopup);
} else {
    setupQuizDeletePopup();
}


/* ==========================================
   MODULE 8 — SECURITY QUIZ SUBMISSION
   ========================================== */

document.addEventListener("DOMContentLoaded", function () {
    const quizContainer = document.getElementById("security-quiz-form");
    const submitButton = document.getElementById("quiz-submit-btn");
    const resultsContainer = document.getElementById("quiz-results");

    if (!quizContainer || !submitButton || !resultsContainer) return;

    submitButton.addEventListener("click", async function () {
        const questionCards = quizContainer.querySelectorAll(".quiz-question-card");
        const answers = {};

        questionCards.forEach(function (card) {
            const selected = card.querySelector('input[type="radio"]:checked');

            if (selected) {
                const questionId = selected.name.replace("question_", "");
                answers[questionId] = selected.value;
            }
        });

        if (Object.keys(answers).length !== questionCards.length) {
    const warningDialog = document.getElementById("quiz-unanswered-dialog");

    if (warningDialog) {
        warningDialog.showModal();
    }

    return;
}

        submitButton.disabled = true;
        submitButton.textContent = "Checking Answers...";

        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content;

            const response = await fetch("/quiz/submit", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfToken
                },
                body: JSON.stringify({ answers: answers })
            });

            const data = await response.json();

            if (!response.ok || !data.success) {
                throw new Error(data.message || "Unable to submit quiz.");
            }

            resultsContainer.replaceChildren();

            const heading = document.createElement("h3");
            heading.textContent = `Your Score: ${data.score}/${data.total} (${data.percentage}%)`;
            resultsContainer.appendChild(heading);

            data.results.forEach(function (result, index) {
                const item = document.createElement("div");
                item.className = "quiz-result-item";

                const status = document.createElement("strong");
                status.textContent = result.is_correct
                    ? `✓ Question ${index + 1}: Correct`
                    : `✗ Question ${index + 1}: Incorrect`;

                const answer = document.createElement("p");
                answer.textContent = `Correct Answer: ${result.correct_answer}`;

                const explanation = document.createElement("p");
                explanation.textContent = result.explanation;

                item.append(status, answer, explanation);
                resultsContainer.appendChild(item);
            });


/* Highlight selected answers after grading */

data.results.forEach(function (result) {
    const card = Array.from(questionCards).find(function (item) {
        return item.querySelector(
            `input[name="question_${result.question_id}"]`
        );
    });

    if (!card) return;

    card.querySelectorAll(".quiz-option").forEach(function (option) {
        const radio = option.querySelector('input[type="radio"]');
        if (!radio) return;

        if (radio.value === result.correct_answer) {
            option.classList.add("quiz-answer-correct");
        } else if (radio.checked && !result.is_correct) {
            option.classList.add("quiz-answer-incorrect");
        }

        radio.disabled = true;
    });
});

/* Add Retake Quiz button */

const retakeButton = document.createElement("button");
retakeButton.type = "button";
retakeButton.className = "quiz-retake-btn";
retakeButton.textContent = "↻ Retake Quiz";

retakeButton.addEventListener("click", function () {
    questionCards.forEach(function (card) {
        card.querySelectorAll(".quiz-option").forEach(function (option) {
            option.classList.remove(
                "quiz-answer-correct",
                "quiz-answer-incorrect"
            );

            const radio = option.querySelector('input[type="radio"]');

            if (radio) {
                radio.checked = false;
                radio.disabled = false;
            }
        });
    });

    resultsContainer.replaceChildren();
    resultsContainer.hidden = true;

    submitButton.disabled = false;
    submitButton.textContent = "Submit Quiz";

    quizContainer.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
});

resultsContainer.appendChild(retakeButton);

            resultsContainer.hidden = false;
            resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });

            submitButton.textContent = "Quiz Submitted";

        } catch (error) {
            resultsContainer.replaceChildren();

            const message = document.createElement("p");
            message.textContent = error.message;
            resultsContainer.appendChild(message);

            resultsContainer.hidden = false;

            submitButton.disabled = false;
            submitButton.textContent = "Submit Quiz";
        }
    });
});


/* MODULE 8 — UNANSWERED QUIZ POPUP */

document.addEventListener("DOMContentLoaded", function () {
    const warningDialog = document.getElementById("quiz-unanswered-dialog");
    const okButton = document.getElementById("quiz-unanswered-ok");

    if (!warningDialog || !okButton) return;

    okButton.addEventListener("click", function () {
        warningDialog.close();
    });
});


/* ==========================================
   MODULE 8 — QUIZ PERFORMANCE CHART
   ========================================== */

document.addEventListener("DOMContentLoaded", function () {
    const canvas = document.getElementById("quiz-performance-chart");
    const dataElement = document.getElementById("quiz-chart-data");

    if (!canvas || !dataElement) return;

    let chartData;

    try {
        chartData = JSON.parse(dataElement.textContent);
    } catch (error) {
        console.error("Unable to load quiz chart data:", error);
        return;
    }

    if (!Array.isArray(chartData) || chartData.length === 0) return;

    const context = canvas.getContext("2d");
    if (!context) return;


    // MODULE 8 — QUIZ CHART TOOLTIP
    const tooltip = document.createElement("div");
    tooltip.className = "quiz-chart-tooltip";
    tooltip.style.cssText = `
        position: absolute;
        display: none;
        pointer-events: none;
        padding: 9px 13px;
        background: #17132b;
        border: 1px solid #a66eff;
        border-radius: 8px;
        color: #00e6ad;
        font: bold 12px Consolas, monospace;
        box-shadow: 0 8px 24px rgba(0,0,0,0.4);
        z-index: 10;
        white-space: nowrap;
    `;

    const chartWrapper = canvas.parentElement;
    chartWrapper.style.position = "relative";
    chartWrapper.appendChild(tooltip);

    let chartPoints = [];

    function drawQuizChart() {
        const container = canvas.parentElement;
        const width = container.clientWidth;
        const height = 300;

        if (width <= 0) return;

        const pixelRatio = window.devicePixelRatio || 1;

        canvas.width = Math.round(width * pixelRatio);
        canvas.height = Math.round(height * pixelRatio);

        canvas.style.width = width + "px";
        canvas.style.height = height + "px";

        context.setTransform(pixelRatio, 0, 0, pixelRatio, 0, 0);
        context.clearRect(0, 0, width, height);

        const left = 52;
        const right = 24;
        const top = 32;
        const bottom = 46;

        const plotWidth = width - left - right;
        const plotHeight = height - top - bottom;

        if (plotWidth <= 0 || plotHeight <= 0) return;

        context.font = "12px Consolas, monospace";
        context.textAlign = "right";
        context.textBaseline = "middle";

        // Draw percentage grid lines
        for (let percentage = 0; percentage <= 100; percentage += 25) {
            const y = top + plotHeight * (1 - percentage / 100);

            context.beginPath();
            context.strokeStyle = "rgba(166, 110, 255, 0.18)";
            context.lineWidth = 1;
            context.moveTo(left, y);
            context.lineTo(width - right, y);
            context.stroke();

            context.fillStyle = "#a99bbf";
            context.fillText(percentage + "%", left - 10, y);
        }

        const points = chartData.map(function (item, index) {
            const percentage = Math.max(
                0,
                Math.min(100, Number(item.percentage) || 0)
            );

            const x = chartData.length === 1
                ? left + plotWidth / 2
                : left + (index / (chartData.length - 1)) * plotWidth;

            const y = top + plotHeight * (1 - percentage / 100);

            return { x, y, percentage };
        });

                chartPoints = points;

        // Draw neon-green connecting line
        if (points.length > 1) {
            context.beginPath();
            context.strokeStyle = "#00e6ad";
            context.lineWidth = 3;
            context.lineJoin = "round";

            points.forEach(function (point, index) {
                if (index === 0) {
                    context.moveTo(point.x, point.y);
                } else {
                    context.lineTo(point.x, point.y);
                }
            });

            context.stroke();
        }

        // Draw score markers and attempt labels
        points.forEach(function (point, index) {
            context.beginPath();
            context.fillStyle = "#00e6ad";
            context.arc(point.x, point.y, 5, 0, Math.PI * 2);
            context.fill();

            context.beginPath();
            context.strokeStyle = "#101827";
            context.lineWidth = 2;
            context.arc(point.x, point.y, 5, 0, Math.PI * 2);
            context.stroke();

            context.fillStyle = "#c59bff";
            context.textAlign = "center";
            context.textBaseline = "top";
            context.fillText(
                "#" + (index + 1),
                point.x,
                height - bottom + 12
            );
        });
    }


    // Show exact score when hovering over a chart point
    canvas.addEventListener("mousemove", function (event) {
        const rect = canvas.getBoundingClientRect();

        const mouseX = event.clientX - rect.left;
        const mouseY = event.clientY - rect.top;

        const hoveredIndex = chartPoints.findIndex(function (point) {
            return Math.hypot(
                point.x - mouseX,
                point.y - mouseY
            ) <= 14;
        });

        if (hoveredIndex === -1) {
            tooltip.style.display = "none";
            return;
        }

        const point = chartPoints[hoveredIndex];

        tooltip.textContent =
            `Attempt #${hoveredIndex + 1}: ${point.percentage}%`;

        tooltip.style.display = "block";

        const tooltipWidth = tooltip.offsetWidth;
        const wrapperWidth = chartWrapper.clientWidth;

        tooltip.style.left =
            Math.max(
                0,
                Math.min(
                    point.x + 12,
                    wrapperWidth - tooltipWidth
                )
            ) + "px";

        tooltip.style.top =
            Math.max(0, point.y - 42) + "px";
    });

    canvas.addEventListener("mouseleave", function () {
        tooltip.style.display = "none";
    });

    drawQuizChart();

    window.addEventListener("resize", drawQuizChart);
});
