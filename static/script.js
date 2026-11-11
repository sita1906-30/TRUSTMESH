/**
 * TRUSTMESH — Frontend Controller (Phase 2)
 * Handles client-side validation, backend API communication,
 * history & analytics polling, signal inspection modal, and safe DOM rendering.
 */

document.addEventListener('DOMContentLoaded', () => {
    // -----------------------------------------------------------------------
    // DOM Element References
    // -----------------------------------------------------------------------
    const form = document.getElementById('analyze-form');
    const messageInput = document.getElementById('message-input');
    const charCount = document.getElementById('char-count');
    const charGuidance = document.getElementById('char-guidance');
    const analyzeBtn = document.getElementById('analyze-btn');
    const btnText = document.getElementById('btn-text');
    const btnSpinner = document.getElementById('btn-spinner');
    const btnIcon = document.getElementById('btn-icon');
    const clearBtn = document.getElementById('clear-btn');

    // Error Banner Elements
    const errorBanner = document.getElementById('error-banner');
    const errorMessage = document.getElementById('error-message');
    const closeErrorBtn = document.getElementById('close-error-btn');

    // Results Section Elements
    const resultsSection = document.getElementById('results-section');
    const riskScore = document.getElementById('risk-score');
    const riskLevel = document.getElementById('risk-level');
    const meterFill = document.getElementById('meter-fill');
    const riskProgressbar = document.getElementById('risk-progressbar');
    const findingsList = document.getElementById('findings-list');
    const recommendationText = document.getElementById('recommendation-text');
    const disclaimerText = document.getElementById('disclaimer-text');
    const urlsCountText = document.getElementById('urls-count-text');

    // History & Analytics Elements (Phase 2)
    const refreshHistoryBtn = document.getElementById('refresh-history-btn');
    const refreshSpinner = document.getElementById('refresh-spinner');
    const refreshIcon = document.getElementById('refresh-icon');
    const historyErrorBanner = document.getElementById('history-error-banner');
    const historyErrorMessage = document.getElementById('history-error-message');
    const historyLoading = document.getElementById('history-loading');
    const historyEmpty = document.getElementById('history-empty');
    const historyTable = document.getElementById('history-table');
    const historyTbody = document.getElementById('history-tbody');

    // Stat Cards
    const statTotal = document.getElementById('stat-total');
    const statHigh = document.getElementById('stat-high');
    const statMed = document.getElementById('stat-med');
    const statLow = document.getElementById('stat-low');
    const statAvg = document.getElementById('stat-avg');
    const topSignalsChips = document.getElementById('top-signals-chips');

    // Signal Inspection Modal
    const signalModal = document.getElementById('signal-modal');
    const modalCloseBtn = document.getElementById('modal-close-btn');
    const modalIncidentTag = document.getElementById('modal-incident-tag');
    const modalRiskScore = document.getElementById('modal-risk-score');
    const modalRiskLevel = document.getElementById('modal-risk-level');
    const modalContentType = document.getElementById('modal-content-type');
    const modalSignalsList = document.getElementById('modal-signals-list');
    const modalRecommendation = document.getElementById('modal-recommendation');

    // Export Report Elements (Phase 4, Task 3: Azure Blob Storage)
    const exportReportBtn = document.getElementById('export-report-btn');
    const saveToCloudCheckbox = document.getElementById('save-to-cloud-checkbox');
    const exportStatusBanner = document.getElementById('export-status-banner');
    const exportStatusText = document.getElementById('export-status-text');
    const modalExportBtn = document.getElementById('modal-export-btn');

    let currentAssessmentId = null;
    let modalActiveAssessmentId = null;

    // Viva Demo Sample Inputs
    const SAMPLE_INPUTS = {
        'urgent-fee': 'URGENT! Pay the registration fee immediately to claim your prize.',
        'sensitive-otp': 'Send your OTP and share your password immediately.',
        'insecure-url': 'http://example.com/login',
        'safe-msg': 'Your appointment is scheduled for tomorrow at 10 AM.'
    };

    // -----------------------------------------------------------------------
    // Helper Functions
    // -----------------------------------------------------------------------

    /**
     * Updates character counter display and warning classes.
     */
    function updateCharCount() {
        const length = messageInput.value.length;
        charCount.textContent = length.toLocaleString();

        if (length > 5000) {
            charGuidance.className = 'char-counter over-limit';
        } else if (length > 4500) {
            charGuidance.className = 'char-counter near-limit';
        } else {
            charGuidance.className = 'char-counter';
        }
    }

    /**
     * Displays an accessible error message in the analyzer error banner.
     */
    function showError(message) {
        errorMessage.textContent = message;
        errorBanner.hidden = false;
        errorBanner.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }

    /**
     * Hides the analyzer error banner.
     */
    function hideError() {
        errorBanner.hidden = true;
        errorMessage.textContent = '';
    }

    /**
     * Shows error for history queries.
     */
    function showHistoryError(message) {
        if (historyErrorMessage && historyErrorBanner) {
            historyErrorMessage.textContent = message;
            historyErrorBanner.hidden = false;
        }
    }

    function hideHistoryError() {
        if (historyErrorBanner) {
            historyErrorBanner.hidden = true;
        }
    }

    /**
     * Toggles the analyze button loading state.
     */
    function setLoading(isLoading) {
        if (isLoading) {
            analyzeBtn.disabled = true;
            analyzeBtn.setAttribute('aria-busy', 'true');
            btnSpinner.style.display = 'inline-block';
            btnIcon.style.display = 'none';
            btnText.textContent = 'Analyzing...';
        } else {
            analyzeBtn.disabled = false;
            analyzeBtn.removeAttribute('aria-busy');
            btnSpinner.style.display = 'none';
            btnIcon.style.display = 'inline-block';
            btnText.textContent = 'Analyze Interaction';
        }
    }

    /**
     * Sets refresh button loading state.
     */
    function setRefreshLoading(isLoading) {
        if (refreshHistoryBtn) {
            refreshHistoryBtn.disabled = isLoading;
            if (refreshSpinner) refreshSpinner.style.display = isLoading ? 'inline-block' : 'none';
            if (refreshIcon) refreshIcon.style.display = isLoading ? 'none' : 'inline-block';
        }
    }

    /**
     * Renders analysis results safely into the DOM.
     */
    function renderResults(data) {
        const score = Number(data.score) || 0;
        const level = data.level || 'Lower detected risk';
        const findings = Array.isArray(data.findings) ? data.findings : [];
        const recommendation = data.recommendation || '';
        const disclaimer = data.disclaimer || 'This preliminary rule-based assessment cannot guarantee that content is safe or fraudulent.';
        const urlsFound = Number(data.urls_found) || 0;

        // 1. Update Score & Text
        riskScore.textContent = String(score);
        riskLevel.textContent = level;

        // 2. Set Risk Category Color Styles
        riskLevel.className = 'risk-level-badge';
        meterFill.className = 'meter-fill';

        if (score >= 60) {
            riskLevel.classList.add('level-high');
            meterFill.classList.add('meter-high');
        } else if (score >= 30) {
            riskLevel.classList.add('level-med');
            meterFill.classList.add('meter-med');
        } else {
            riskLevel.classList.add('level-low');
            meterFill.classList.add('meter-low');
        }

        // 3. Update Visual Meter
        meterFill.style.width = `${Math.min(Math.max(score, 0), 100)}%`;
        riskProgressbar.setAttribute('aria-valuenow', String(score));

        // 4. Update URLs Found Indicator
        urlsCountText.textContent = `${urlsFound} URL${urlsFound === 1 ? '' : 's'} Identified`;

        // 5. Render Detected Findings List safely using textContent
        while (findingsList.firstChild) {
            findingsList.removeChild(findingsList.firstChild);
        }

        if (findings.length === 0) {
            const li = document.createElement('li');
            li.className = 'finding-item finding-none';
            li.textContent = 'No configured warning patterns were detected. This does not prove the content is safe.';
            findingsList.appendChild(li);
        } else {
            findings.forEach((finding) => {
                const li = document.createElement('li');
                li.className = 'finding-item';
                if (finding.includes('No configured warning patterns')) {
                    li.classList.add('finding-none');
                }
                li.textContent = finding;
                findingsList.appendChild(li);
            });
        }

        // 6. Update Recommendation & Disclaimer
        recommendationText.textContent = recommendation;
        disclaimerText.textContent = disclaimer;

        // 7. Store active assessment ID for export & reset status
        currentAssessmentId = data.assessment_id || null;
        if (exportStatusBanner) exportStatusBanner.hidden = true;

        // 8. Reveal Results Section and Smooth Scroll
        resultsSection.hidden = false;
        resultsSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // -----------------------------------------------------------------------
    // Phase 2: History & Analytics Integration
    // -----------------------------------------------------------------------

    /**
     * Formats timestamp string safely into a readable locale string.
     */
    function formatDateTime(timestampStr) {
        if (!timestampStr) return 'N/A';
        try {
            const date = new Date(timestampStr.replace(' ', 'T') + 'Z');
            return isNaN(date.getTime()) ? timestampStr : date.toLocaleString();
        } catch {
            return timestampStr;
        }
    }

    /**
     * Opens the modal dialog to safely inspect detected signals for a historical incident.
     */
    function openSignalInspection(item) {
        if (!signalModal) return;

        modalActiveAssessmentId = item.assessment_id || null;
        modalIncidentTag.textContent = `Incident #${item.incident_id}`;
        modalRiskScore.textContent = `${item.risk_score} / 100`;
        modalRiskLevel.textContent = item.risk_level;
        modalRiskLevel.className = 'risk-level-badge';

        if (item.risk_score >= 60) {
            modalRiskLevel.classList.add('level-high');
        } else if (item.risk_score >= 30) {
            modalRiskLevel.classList.add('level-med');
        } else {
            modalRiskLevel.classList.add('level-low');
        }

        modalContentType.textContent = item.content_type || 'message';
        modalRecommendation.textContent = item.recommendation || 'No recommendation stored.';

        // Populate signals list safely
        while (modalSignalsList.firstChild) {
            modalSignalsList.removeChild(modalSignalsList.firstChild);
        }

        const signals = Array.isArray(item.signals) ? item.signals : [];
        if (signals.length === 0) {
            const li = document.createElement('li');
            li.className = 'modal-signal-item';
            const span = document.createElement('span');
            span.className = 'modal-signal-desc';
            span.textContent = 'No specific warning signals were recorded for this incident.';
            li.appendChild(span);
            modalSignalsList.appendChild(li);
        } else {
            signals.forEach(sig => {
                const li = document.createElement('li');
                li.className = 'modal-signal-item';

                const infoDiv = document.createElement('div');
                infoDiv.className = 'modal-signal-info';

                const nameSpan = document.createElement('span');
                nameSpan.className = 'modal-signal-name';
                nameSpan.textContent = sig.category ? `${sig.category} (${sig.signal_name})` : sig.signal_name;

                const descSpan = document.createElement('span');
                descSpan.className = 'modal-signal-desc';
                descSpan.textContent = sig.description || '';

                infoDiv.appendChild(nameSpan);
                infoDiv.appendChild(descSpan);

                const ptsSpan = document.createElement('span');
                ptsSpan.className = 'modal-signal-points';
                ptsSpan.textContent = `+${sig.points_awarded} pts`;

                li.appendChild(infoDiv);
                li.appendChild(ptsSpan);
                modalSignalsList.appendChild(li);
            });
        }

        // Show HTML5 Dialog
        if (typeof signalModal.showModal === 'function') {
            signalModal.showModal();
        } else {
            signalModal.setAttribute('open', '');
        }
    }

    /**
     * Fetches analysis history from /api/history and updates the table.
     */
    async function fetchHistory() {
        hideHistoryError();
        if (historyLoading) historyLoading.hidden = false;
        if (historyEmpty) historyEmpty.hidden = true;
        if (historyTable) historyTable.hidden = true;

        try {
            const response = await fetch('/api/history', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });

            if (response.status === 401) {
                if (historyEmpty) {
                    historyEmpty.hidden = false;
                    const emptyTitle = historyEmpty.querySelector('.empty-title');
                    const emptyDesc = historyEmpty.querySelector('.empty-desc');
                    if (emptyTitle) emptyTitle.textContent = 'Personal History Requires Sign In';
                    if (emptyDesc) emptyDesc.textContent = 'Sign in or create an account to record your evaluations in your personal digital trust history.';
                }
                if (historyTable) historyTable.hidden = true;
                return;
            }

            if (!response.ok) {
                throw new Error(`History query failed with status: ${response.status}`);
            }

            const data = await response.json();
            const history = Array.isArray(data.history) ? data.history : [];

            // Clear existing rows safely
            while (historyTbody.firstChild) {
                historyTbody.removeChild(historyTbody.firstChild);
            }

            if (history.length === 0) {
                if (historyEmpty) historyEmpty.hidden = false;
                if (historyTable) historyTable.hidden = true;
            } else {
                if (historyEmpty) historyEmpty.hidden = true;
                if (historyTable) historyTable.hidden = false;

                history.forEach(item => {
                    const tr = document.createElement('tr');

                    // 1. Incident ID
                    const tdId = document.createElement('td');
                    tdId.className = 'table-incident-id';
                    tdId.textContent = `#${item.incident_id}`;
                    tr.appendChild(tdId);

                    // 2. Date & Time
                    const tdDate = document.createElement('td');
                    tdDate.textContent = formatDateTime(item.created_at);
                    tr.appendChild(tdDate);

                    // 3. Type
                    const tdType = document.createElement('td');
                    const typePill = document.createElement('span');
                    typePill.className = 'table-type-pill';
                    typePill.textContent = item.content_type || 'message';
                    tdType.appendChild(typePill);
                    tr.appendChild(tdType);

                    // 4. Risk Level
                    const tdLevel = document.createElement('td');
                    const levelBadge = document.createElement('span');
                    levelBadge.className = 'risk-level-badge';
                    levelBadge.textContent = item.risk_level;
                    if (item.risk_score >= 60) {
                        levelBadge.classList.add('level-high');
                    } else if (item.risk_score >= 30) {
                        levelBadge.classList.add('level-med');
                    } else {
                        levelBadge.classList.add('level-low');
                    }
                    tdLevel.appendChild(levelBadge);
                    tr.appendChild(tdLevel);

                    // 5. Score
                    const tdScore = document.createElement('td');
                    tdScore.className = 'table-score';
                    tdScore.textContent = `${item.risk_score} / 100`;
                    tr.appendChild(tdScore);

                    // 6. Signals Count
                    const tdSignals = document.createElement('td');
                    const signalCount = item.signal_count !== undefined ? item.signal_count : (item.signals ? item.signals.length : 0);
                    tdSignals.textContent = `${signalCount} signal${signalCount === 1 ? '' : 's'}`;
                    tr.appendChild(tdSignals);

                    // 7. Inspect Action Button
                    const tdAction = document.createElement('td');
                    const inspectBtn = document.createElement('button');
                    inspectBtn.type = 'button';
                    inspectBtn.className = 'inspect-btn';
                    inspectBtn.textContent = 'View Signals';
                    inspectBtn.title = `Inspect signals for Incident #${item.incident_id}`;
                    inspectBtn.addEventListener('click', () => openSignalInspection(item));
                    tdAction.appendChild(inspectBtn);
                    tr.appendChild(tdAction);

                    historyTbody.appendChild(tr);
                });
            }
        } catch (err) {
            console.error('Error fetching history:', err);
            showHistoryError('Unable to load history records from SQLite database.');
            if (historyEmpty) historyEmpty.hidden = false;
        } finally {
            if (historyLoading) historyLoading.hidden = true;
        }
    }

    /**
     * Fetches platform analytics from /api/analytics and updates stat cards.
     */
    async function fetchAnalytics() {
        try {
            const response = await fetch('/api/analytics', {
                method: 'GET',
                headers: { 'Accept': 'application/json' }
            });

            if (!response.ok) return;

            const data = await response.json();
            const a = data.analytics || {};

            if (statTotal) statTotal.textContent = String(a.total_analyses || 0);
            if (statHigh) statHigh.textContent = String(a.high_risk_count || 0);
            if (statMed) statMed.textContent = String(a.suspicious_count || 0);
            if (statLow) statLow.textContent = String(a.lower_risk_count || 0);
            if (statAvg) statAvg.textContent = Number(a.average_score || 0).toFixed(1);

            // Populate top signals chips
            if (topSignalsChips) {
                while (topSignalsChips.firstChild) {
                    topSignalsChips.removeChild(topSignalsChips.firstChild);
                }

                const topSignals = Array.isArray(a.top_signals) ? a.top_signals : [];
                if (topSignals.length === 0) {
                    const span = document.createElement('span');
                    span.className = 'stat-meta';
                    span.textContent = 'No warning signals recorded yet.';
                    topSignalsChips.appendChild(span);
                } else {
                    topSignals.forEach(sig => {
                        const chip = document.createElement('div');
                        chip.className = 'signal-chip';

                        const label = document.createElement('span');
                        label.textContent = sig.category ? `${sig.category}` : sig.signal_name;

                        const count = document.createElement('span');
                        count.className = 'signal-chip-count';
                        count.textContent = `${sig.frequency}x`;

                        chip.appendChild(label);
                        chip.appendChild(count);
                        topSignalsChips.appendChild(chip);
                    });
                }
            }
        } catch (err) {
            console.error('Error fetching analytics:', err);
        }
    }

    /**
     * Refreshes both history and analytics, and updates live database connection status.
     */
    async function updateDbStatus() {
        try {
            const res = await fetch('/health');
            if (res.ok) {
                const data = await res.json();
                const badgeText = document.getElementById('db-status-text');
                const badgeContainer = document.getElementById('db-status-badge');
                const pulse = badgeContainer ? badgeContainer.querySelector('.status-pulse') : null;
                if (badgeText && data.database_status_indicator) {
                    badgeText.textContent = data.database_status_indicator;
                }
                if (badgeContainer && data.database_details) {
                    badgeContainer.title = data.database_details;
                }
                if (pulse) {
                    pulse.className = 'status-pulse';
                    if (data.status !== 'healthy') {
                        pulse.classList.add('status-pulse-offline');
                    } else if (data.is_cloud) {
                        pulse.classList.add('status-pulse-cloud');
                    }
                }
            }
        } catch {
            // Non-blocking background telemetry update
        }
    }

    async function refreshDashboard() {
        setRefreshLoading(true);
        await Promise.allSettled([fetchHistory(), fetchAnalytics(), updateDbStatus()]);
        setRefreshLoading(false);
    }

    // -----------------------------------------------------------------------
    // Phase 4, Task 3: Export Report & Azure Blob Storage Handlers
    // -----------------------------------------------------------------------

    function showExportStatus(message, type = 'success') {
        if (!exportStatusBanner || !exportStatusText) return;
        exportStatusText.textContent = message;
        exportStatusBanner.className = 'export-status-banner';
        if (type === 'warning') exportStatusBanner.classList.add('status-warning');
        if (type === 'error') exportStatusBanner.classList.add('status-error');
        exportStatusBanner.hidden = false;
    }

    function hideExportStatus() {
        if (exportStatusBanner) exportStatusBanner.hidden = true;
    }

    async function handleExportReport(assessmentId, saveToCloud) {
        if (!assessmentId) {
            showError('Unable to export: Assessment ID is missing. Please run an analysis first.');
            return;
        }

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        const reqHeaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        if (csrfToken) reqHeaders['X-CSRFToken'] = csrfToken;

        showExportStatus('Preparing assessment report...', 'info');

        try {
            const response = await fetch('/api/reports/export', {
                method: 'POST',
                headers: reqHeaders,
                body: JSON.stringify({
                    assessment_id: assessmentId,
                    save_to_cloud: Boolean(saveToCloud)
                })
            });

            const data = await response.json();
            if (!response.ok) {
                if (response.status === 401) {
                    showExportStatus('Please sign in to export and download assessment reports.', 'warning');
                } else {
                    showExportStatus(data.error || 'Export request failed.', 'error');
                }
                return;
            }

            // Trigger local download of formatted JSON
            if (data.report_data) {
                const blob = new Blob([JSON.stringify(data.report_data, null, 2)], { type: 'application/json' });
                const downloadUrl = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = downloadUrl;
                a.download = `trustmesh_report_asm_${assessmentId}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(downloadUrl);
            }

            const bannerType = data.storage_status === 'UPLOADED' ? 'success' : (saveToCloud ? 'warning' : 'success');
            showExportStatus(data.message || 'Report exported successfully.', bannerType);

        } catch (netErr) {
            console.error('Export network error:', netErr);
            showExportStatus('Unable to reach the report export service. Check backend connectivity.', 'error');
        }
    }

    // -----------------------------------------------------------------------
    // Event Listeners
    // -----------------------------------------------------------------------

    // Live character counter
    messageInput.addEventListener('input', updateCharCount);

    // Close error banner button
    closeErrorBtn.addEventListener('click', hideError);

    // Reset / Clear button
    clearBtn.addEventListener('click', () => {
        messageInput.value = '';
        updateCharCount();
        hideError();
        resultsSection.hidden = true;
        messageInput.focus();
    });

    // Quick viva demo buttons
    document.querySelectorAll('.sample-chip').forEach((button) => {
        button.addEventListener('click', () => {
            const sampleKey = button.getAttribute('data-sample');
            if (SAMPLE_INPUTS[sampleKey]) {
                messageInput.value = SAMPLE_INPUTS[sampleKey];
                updateCharCount();
                hideError();
                messageInput.focus();
            }
        });
    });

    // Refresh history button listener
    if (refreshHistoryBtn) {
        refreshHistoryBtn.addEventListener('click', refreshDashboard);
    }

    // Modal dialog close listeners
    if (modalCloseBtn && signalModal) {
        modalCloseBtn.addEventListener('click', () => {
            if (typeof signalModal.close === 'function') {
                signalModal.close();
            } else {
                signalModal.removeAttribute('open');
            }
        });

        // Close on backdrop click
        signalModal.addEventListener('click', (event) => {
            if (event.target === signalModal) {
                if (typeof signalModal.close === 'function') {
                    signalModal.close();
                } else {
                    signalModal.removeAttribute('open');
                }
            }
        });
    }

    // Export assessment report buttons
    if (exportReportBtn) {
        exportReportBtn.addEventListener('click', () => {
            const saveToCloud = saveToCloudCheckbox ? saveToCloudCheckbox.checked : false;
            handleExportReport(currentAssessmentId, saveToCloud);
        });
    }

    if (modalExportBtn) {
        modalExportBtn.addEventListener('click', () => {
            handleExportReport(modalActiveAssessmentId, false);
        });
    }

    // Form submission handler
    form.addEventListener('submit', async (event) => {
        event.preventDefault();
        hideError();

        const rawText = messageInput.value;
        const trimmedText = rawText.trim();

        // Client-side validations
        if (!trimmedText) {
            showError('Please enter a message or URL before requesting analysis.');
            messageInput.focus();
            return;
        }

        if (rawText.length > 5000) {
            showError('Input exceeds the maximum limit of 5,000 characters. Please shorten your text.');
            messageInput.focus();
            return;
        }

        setLoading(true);

        const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content');
        const reqHeaders = {
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        };
        if (csrfToken) {
            reqHeaders['X-CSRFToken'] = csrfToken;
        }

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: reqHeaders,
                body: JSON.stringify({ text: rawText })
            });

            const data = await response.json();

            if (!response.ok) {
                const serverError = data && data.error ? data.error : `Server returned status ${response.status}.`;
                showError(serverError);
                return;
            }

            // Successfully received analysis result
            renderResults(data);

            // Automatically refresh history table and analytics metrics in background!
            fetchHistory();
            fetchAnalytics();

        } catch (networkError) {
            console.error('Fetch error:', networkError);
            showError('Unable to connect to the TRUSTMESH analysis service. Ensure the local Flask backend is running.');
        } finally {
            setLoading(false);
        }
    });

    // Initial character count update and dashboard load
    updateCharCount();
    refreshDashboard();
});
