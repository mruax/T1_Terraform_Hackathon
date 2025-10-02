// Terraform Log Viewer 3.0 - JavaScript

// ==================== STATE ====================

let allLogs = [];
let filteredLogs = [];
let activeLevels = new Set(['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL']);
let chainFilter = 'all';
let hideRead = false;
let readLogs = new Set(JSON.parse(localStorage.getItem('readLogs') || '[]'));
let currentFileId = null;
let currentPage = 1;
let logsPerPage = 50;
let ganttData = null;
let ganttZoom = 1.0;
let collapsedSections = new Set();
let metricsChart = null;
let requestChains = {};
let sectionNumbers = {};
let sidebarCollapsed = false;
let currentTab = 'logs';
let ganttScrollPos = { left: 0, top: 0 };
let ganttScrollContainer = null;

const API_BASE = '';

// Swimlane colors
const swimlaneColors = [
    '#007aff', '#34c759', '#ff9500', '#ff3b30', '#5856d6',
    '#00c7be', '#ff2d55', '#5ac8fa', '#ffcc00', '#af52de'
];

// ==================== INITIALIZATION ====================

const uploadBox = document.getElementById('uploadBox');
const fileInput = document.getElementById('fileInput');

uploadBox.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFileSelect);

uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadBox.style.borderColor = '#1d1d1f';
});

uploadBox.addEventListener('dragleave', () => {
    uploadBox.style.borderColor = '#d2d2d7';
});

uploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadBox.style.borderColor = '#d2d2d7';
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file);
});

document.getElementById('searchInput').addEventListener('input', () => {
    currentPage = 1;
    filterAndDisplay();
});

document.getElementById('ganttChart').addEventListener('wheel', (e) => {
    if (e.ctrlKey || e.metaKey) {
        e.preventDefault();
        
        const chartContainer = document.getElementById('ganttChart');
        const rect = chartContainer.getBoundingClientRect();
        const mouseX = e.clientX - rect.left;
        const mouseY = e.clientY - rect.top;
        
        const contentX = (chartContainer.scrollLeft + mouseX) / chartContainer.scrollWidth;
        
        const delta = e.deltaY > 0 ? -1 : 1;
        const oldZoom = ganttZoom;
        zoomGantt(delta);
        
        requestAnimationFrame(() => {
            const newScrollLeft = (contentX * chartContainer.scrollWidth) - mouseX;
            chartContainer.scrollLeft = Math.max(0, newScrollLeft);
        });
    }
}, { passive: false });

// Load file list on page load
loadFileList();

// ==================== UI FUNCTIONS ====================

function toggleSidebar() {
    sidebarCollapsed = !sidebarCollapsed;
    const sidebar = document.getElementById('sidebar');
    const layout = document.getElementById('mainLayout');
    const toggle = document.querySelector('.sidebar-toggle');
    
    if (sidebarCollapsed) {
        sidebar.classList.add('collapsed');
        layout.classList.add('sidebar-collapsed');
        toggle.textContent = '▶';
    } else {
        sidebar.classList.remove('collapsed');
        layout.classList.remove('sidebar-collapsed');
        toggle.textContent = '◀';
    }
}

function switchTab(tabName) {
    currentTab = tabName;
    
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
    
    event.target.classList.add('active');
    document.getElementById(`${tabName}-tab`).classList.add('active');

    updateFileListDisplay();

    if (tabName === 'gantt' && currentFileId) {
        loadGanttData(currentFileId);
    } else if (tabName === 'monitoring') {
        loadMonitoringData();
    }
}

function updateFileListDisplay() {
    const fileItems = document.querySelectorAll('.file-item');
    fileItems.forEach(item => {
        const deleteBtn = item.querySelector('.delete-btn');
        const stats = item.querySelector('.file-item-stats');
        
        if (currentTab === 'gantt' || currentTab === 'monitoring') {
            if (!deleteBtn) deleteBtn.style.display = sidebarCollapsed ? 'block' : 'none';
            if (stats) {
                const badges = stats.querySelectorAll('.stat-badge');
                badges.forEach(badge => badge.style.display = 'none');
            }
        } else {
            if (!deleteBtn) {
                deleteBtn.style.display = sidebarCollapsed ? 'none' : 'block';
            }
            if (stats) {
                const badges = stats.querySelectorAll('.stat-badge');
                badges.forEach(badge => badge.style.display = 'inline-block');
            }
        }
    });
}

// ==================== PROGRESS FUNCTIONS ====================

function showProgress(title = 'Processing...') {
    const modal = document.getElementById('progressModal');
    document.getElementById('progressTitle').textContent = title;
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressText').textContent = '0%';
    document.getElementById('progressStatus').textContent = '';
    modal.classList.add('visible');
}

function updateProgress(percent, status = '') {
    document.getElementById('progressBar').style.width = percent + '%';
    document.getElementById('progressText').textContent = Math.round(percent) + '%';
    if (status) {
        document.getElementById('progressStatus').textContent = status;
    }
}

function hideProgress(delay = 0) {
    setTimeout(() => {
        document.getElementById('progressModal').classList.remove('visible');
    }, delay);
}

// ==================== FILE UPLOAD ====================

function handleFileSelect(e) {
    const file = e.target.files[0];
    if (file) uploadFile(file);
}

async function uploadFile(file) {
    const formData = new FormData();
    formData.append('file', file);

    showProgress('Uploading file...');
    updateProgress(10, 'Reading file...');

    try {
        updateProgress(30, 'Sending to server...');
        
        const response = await fetch(`${API_BASE}/upload-log/?config=default`, {
            method: 'POST',
            body: formData
        });

        updateProgress(60, 'Processing logs...');
        const data = await response.json();
        
        if (response.status === 409) {
            updateProgress(100, '');
            document.getElementById('progressStatus').textContent = 'File already exists!';
            document.getElementById('progressStatus').classList.add('error');
            hideProgress(2000);
            return;
        }
        
        if (data.status === 'success') {
            updateProgress(90, 'Finalizing...');
            await loadFileList();
            updateProgress(100, 'Success!');
            document.getElementById('progressStatus').classList.remove('error');
            hideProgress(1500);
            loadLogFile(data.file_id);
        }
    } catch (error) {
        console.error('Upload error:', error);
        updateProgress(100, '');
        document.getElementById('progressStatus').textContent = 'Upload failed!';
        document.getElementById('progressStatus').classList.add('error');
        hideProgress(3000);
    }
}

// ==================== FILE LIST ====================

async function loadFileList() {
    try {
        const response = await fetch(`${API_BASE}/logs/`);
        const files = await response.json();

        const fileList = document.getElementById('fileList');
        
        if (files.length === 0) {
            fileList.innerHTML = '<div class="empty-state"><p>No files uploaded</p></div>';
            return;
        }

        fileList.innerHTML = files.map((f, index) => `
            <div class="file-item ${f.id === currentFileId ? 'active' : ''}" onclick="selectLogFile(${f.id})">
                <button class="delete-btn" onclick="deleteLogFile(${f.id}, event)">×</button>
                <div class="file-item-name" title="${f.filename} (ID: ${f.id})">
                    <span class="file-number">${f.id}.</span>
                    <span class="file-full-name">${f.filename}</span>
                </div>
                <div class="file-item-stats">
                    <span>${f.total_entries} logs</span>
                    ${f.error_count > 0 ? `<span class="stat-badge error">${f.error_count} E</span>` : ''}
                    ${f.warn_count > 0 ? `<span class="stat-badge warn">${f.warn_count} W</span>` : ''}
                </div>
            </div>
        `).join('');

        updateFileListDisplay();
    } catch (error) {
        console.error('Error loading file list:', error);
    }
}

function selectLogFile(fileId) {
    loadLogFile(fileId);
    if (currentTab === 'gantt') {
        loadGanttData(fileId);
    }
}

async function deleteLogFile(fileId, event) {
    event.stopPropagation();
    
    if (!confirm('Delete this log file?')) return;

    try {
        await fetch(`${API_BASE}/logs/${fileId}`, { method: 'DELETE' });
        
        if (currentFileId === fileId) {
            currentFileId = null;
            allLogs = [];
            document.getElementById('logsContainer').innerHTML = '<div class="empty-state"><p>No logs loaded</p></div>';
            document.getElementById('controls').style.display = 'none';
            document.getElementById('pagination').style.display = 'none';
        }
        
        await loadFileList();
    } catch (error) {
        console.error('Error deleting file:', error);
    }
}

// ==================== LOG FILE LOADING ====================

async function loadLogFile(fileId) {
    currentFileId = fileId;
    currentPage = 1;
    
    showProgress('Loading log file...');
    updateProgress(20, 'Fetching data...');
    
    try {
        const response = await fetch(`${API_BASE}/logs/${fileId}`);
        const data = await response.json();

        updateProgress(60, 'Processing entries...');

        allLogs = data.entries.map((e, idx) => ({
            ...e,
            timestamp: e.timestamp,
            originalIndex: idx
        }));

        requestChains = data.request_chains || {};

        sectionNumbers = {};
        let sectionCounter = 1;
        const seenSections = new Set();
        
        allLogs.forEach(log => {
            const section = log.section_type || 'general';
            if (!seenSections.has(section)) {
                seenSections.add(section);
                sectionNumbers[section] = sectionCounter++;
            }
        });

        updateProgress(90, 'Rendering...');

        createLevelFilters();
        filterAndDisplay();
        document.getElementById('controls').style.display = 'flex';
        document.getElementById('pagination').style.display = 'flex';
        
        await loadFileList();
        
        updateProgress(100, 'Done!');
        hideProgress(800);
    } catch (error) {
        console.error('Error loading log file:', error);
        document.getElementById('progressStatus').textContent = 'Failed to load file!';
        document.getElementById('progressStatus').classList.add('error');
        hideProgress(3000);
    }
}

// ==================== FILTERS ====================

function createLevelFilters() {
    const levels = ['TRACE', 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'];
    const container = document.getElementById('levelFilters');
    
    container.innerHTML = levels.map(level => 
        `<button class="level-btn ${level} active" onclick="toggleLevel('${level}')">${level}</button>`
    ).join('');
}

function toggleLevel(level) {
    const btn = event.target;
    btn.classList.toggle('active');
    
    if (activeLevels.has(level)) {
        activeLevels.delete(level);
    } else {
        activeLevels.add(level);
    }
    
    currentPage = 1;
    filterAndDisplay();
}

function toggleHideRead() {
    hideRead = !hideRead;
    const btn = document.getElementById('hideReadToggle');
    btn.classList.toggle('active');
    btn.textContent = hideRead ? '👁️ Show All' : '👁️ Hide Read';
    currentPage = 1;
    filterAndDisplay();
}

function toggleChainFilter() {
    const states = ['all', 'with_chain', 'no_chain'];
    const labels = {
        'all': '🔗 All Chains',
        'with_chain': '🔗 With Chain',
        'no_chain': '🔗 No Chain'
    };
    
    const currentIndex = states.indexOf(chainFilter);
    chainFilter = states[(currentIndex + 1) % states.length];
    
    const btn = document.getElementById('chainFilterToggle');
    btn.textContent = labels[chainFilter];
    btn.classList.toggle('active', chainFilter !== 'all');
    
    currentPage = 1;
    filterAndDisplay();
}

function toggleAdvancedSearch() {
    const search = document.getElementById('advancedSearch');
    search.classList.toggle('visible');
}

function applyAdvancedFilters() {
    currentPage = 1;
    filterAndDisplay();
}

function resetAdvancedFilters() {
    document.getElementById('filterProvider').value = '';
    document.getElementById('filterResource').value = '';
    document.getElementById('filterSection').value = '';
    document.getElementById('filterDateFrom').value = '';
    document.getElementById('filterDateTo').value = '';
    document.getElementById('filterRegex').value = '';
    currentPage = 1;
    filterAndDisplay();
}

function changePerPage() {
    logsPerPage = parseInt(document.getElementById('perPageInput').value) || 50;
    logsPerPage = Math.max(10, Math.min(500, logsPerPage));
    document.getElementById('perPageInput').value = logsPerPage;
    currentPage = 1;
    filterAndDisplay();
}

function filterAndDisplay() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const provider = document.getElementById('filterProvider')?.value || '';
    const resource = document.getElementById('filterResource')?.value.toLowerCase() || '';
    const section = document.getElementById('filterSection')?.value || '';
    const dateFrom = document.getElementById('filterDateFrom')?.value || '';
    const dateTo = document.getElementById('filterDateTo')?.value || '';
    const regexPattern = document.getElementById('filterRegex')?.value || '';
    
    let regex = null;
    if (regexPattern) {
        try {
            regex = new RegExp(regexPattern, 'i');
        } catch (e) {
            console.error('Invalid regex:', e);
        }
    }
    
    filteredLogs = allLogs.filter(log => {
        const matchesLevel = activeLevels.has(log.level);
        const matchesSearch = !searchTerm || log.message.toLowerCase().includes(searchTerm);
        const matchesRead = !hideRead || !readLogs.has(log.originalIndex);
        
        let matchesChain = true;
        if (chainFilter === 'with_chain') {
            matchesChain = log.req_id && requestChains[log.req_id];
        } else if (chainFilter === 'no_chain') {
            matchesChain = !log.req_id || !requestChains[log.req_id];
        }
        
        let matchesProvider = true;
        if (provider) {
            matchesProvider = log.message.toLowerCase().includes(provider);
        }
        
        let matchesResource = true;
        if (resource) {
            matchesResource = log.message.toLowerCase().includes(resource);
        }
        
        let matchesSection = true;
        if (section) {
            matchesSection = log.section_type === section;
        }
        
        let matchesDate = true;
        if (dateFrom || dateTo) {
            const logDate = new Date(log.timestamp);
            if (dateFrom) matchesDate = logDate >= new Date(dateFrom);
            if (dateTo && matchesDate) matchesDate = logDate <= new Date(dateTo);
        }
        
        let matchesRegex = true;
        if (regex) {
            matchesRegex = regex.test(log.message);
        }
        
        return matchesLevel && matchesSearch && matchesRead && matchesChain &&
               matchesProvider && matchesResource && matchesSection && matchesDate && matchesRegex;
    });
    
    displayLogs();
}

// ==================== DISPLAY LOGS ====================

function toggleSectionCollapse(sectionName) {
    if (collapsedSections.has(sectionName)) {
        collapsedSections.delete(sectionName);
    } else {
        collapsedSections.add(sectionName);
    }
    displayLogs();
}

function displayLogs() {
    const container = document.getElementById('logsContainer');
    
    if (filteredLogs.length === 0) {
        container.innerHTML = '<div class="empty-state"><p>No results found</p></div>';
        updatePagination();
        return;
    }
    
    const startIdx = (currentPage - 1) * logsPerPage;
    const endIdx = startIdx + logsPerPage;
    const pageLog = filteredLogs.slice(startIdx, endIdx);
    
    const sections = {};
    pageLog.forEach(log => {
        const section = log.section_type || 'general';
        if (!sections[section]) {
            sections[section] = [];
        }
        sections[section].push(log);
    });
    
    const sectionCounts = {};
    filteredLogs.forEach(log => {
        const section = log.section_type || 'general';
        if (!sectionCounts[section]) {
            sectionCounts[section] = { total: 0, errors: 0, warnings: 0 };
        }
        sectionCounts[section].total++;
        if (log.level === 'ERROR') sectionCounts[section].errors++;
        if (log.level === 'WARN') sectionCounts[section].warnings++;
    });
    
    let html = '';
    
    Object.keys(sections).forEach(sectionName => {
        const logs = sections[sectionName];
        const stats = sectionCounts[sectionName];
        const sectionNum = sectionNumbers[sectionName] || 0;
        const isCollapsed = collapsedSections.has(sectionName);
        
        html += `
            <div class="section-group">
                <div class="section-header" onclick="toggleSectionCollapse('${sectionName}')">
                    <div class="section-title">
                        <span class="section-number">№${sectionNum}</span>
                        <span>${sectionName.toUpperCase()}</span>
                    </div>
                    <span class="section-stats">
                        ${stats.total} logs
                        ${stats.errors > 0 ? ` · ${stats.errors} errors` : ''}
                        ${stats.warnings > 0 ? ` · ${stats.warnings} warnings` : ''}
                    </span>
                    <button class="section-collapse-btn ${isCollapsed ? 'collapsed' : ''}">▼</button>
                </div>
                <div class="section-content ${isCollapsed ? 'collapsed' : ''}">
        `;
        
        logs.forEach(log => {
            const isRead = readLogs.has(log.originalIndex);
            const hasChain = log.req_id && requestChains[log.req_id];
            const chainLength = hasChain ? requestChains[log.req_id].length : 0;
            
            html += `
                <div class="log-entry ${log.level} ${isRead ? 'read' : ''} ${hasChain ? 'has-chain' : ''}" id="log-${log.originalIndex}">
                    <div class="entry-actions">
                        ${!isRead ? '<div class="unread-badge"></div>' : ''}
                        ${hasChain ? `<div class="chain-indicator" onclick="showChainDetails('${log.req_id}')">🔗 ${chainLength}</div>` : ''}
                        <button class="mark-read-btn" onclick="markAsRead(${log.originalIndex})">
                            ${isRead ? '↻ Unread' : '✓ Read'}
                        </button>
                    </div>
                    <div class="log-header">
                        <span class="log-timestamp">${formatTimestampFull(log.timestamp)}</span>
                        <span class="log-level ${log.level}">${log.level}</span>
                    </div>
                    <div style="line-height: 1.6;">${escapeHtml(log.message)}</div>
                </div>
            `;
        });
        
        html += `
                </div>
            </div>
        `;
    });
    
    container.innerHTML = html;
    updatePagination();
}

function markAsRead(idx) {
    if (readLogs.has(idx)) {
        readLogs.delete(idx);
    } else {
        readLogs.add(idx);
    }
    
    localStorage.setItem('readLogs', JSON.stringify([...readLogs]));
    filterAndDisplay();
}

// ==================== PAGINATION ====================

function updatePagination() {
    const totalPages = Math.ceil(filteredLogs.length / logsPerPage);
    document.getElementById('pageInfo').textContent = `Page ${currentPage} of ${totalPages} (${filteredLogs.length} logs)`;
    document.getElementById('prevBtn').disabled = currentPage === 1;
    document.getElementById('nextBtn').disabled = currentPage >= totalPages;
    document.getElementById('pageJumpInput').max = totalPages;
}

function changePage(delta) {
    currentPage += delta;
    displayLogs();
    document.getElementById('logsContainer').scrollTop = 0;
}

function jumpToPage() {
    const pageInput = document.getElementById('pageJumpInput');
    const targetPage = parseInt(pageInput.value);
    const totalPages = Math.ceil(filteredLogs.length / logsPerPage);
    
    if (targetPage && targetPage >= 1 && targetPage <= totalPages) {
        currentPage = targetPage;
        displayLogs();
        document.getElementById('logsContainer').scrollTop = 0;
    } else {
        alert(`Please enter a page number between 1 and ${totalPages}`);
    }
    
    pageInput.value = '';
}

// ==================== CHAIN MODAL ====================

function showChainDetails(reqId) {
    if (!requestChains[reqId]) return;
    
    const chainIndices = requestChains[reqId];
    const chainLogs = chainIndices.map(idx => allLogs[idx]).filter(l => l);
    
    if (chainLogs.length === 0) return;
    
    let html = `<p style="margin-bottom: 16px; color: #6e6e73; font-size: 14px;">Request ID: <strong>${reqId}</strong> · ${chainLogs.length} logs</p>`;
    
    chainLogs.forEach((log, i) => {
        const section = log.section_type || 'general';
        const sectionNum = sectionNumbers[section] || 0;
        const logPageNumber = Math.floor(filteredLogs.indexOf(log) / logsPerPage) + 1;
        
        html += `
            <div class="chain-log-item" onclick="navigateToLog(${log.originalIndex}, '${section}', ${logPageNumber})">
                <div class="chain-log-header">
                    <span class="chain-log-number">#${i + 1}</span>
                    <span class="log-level ${log.level}">${log.level}</span>
                    <span class="chain-log-timestamp">${formatTimestampFull(log.timestamp)}</span>
                    <span style="font-size: 11px; color: #6e6e73;">→ Section №${sectionNum} · Page ${logPageNumber || '?'}</span>
                </div>
                <div class="chain-log-message">${escapeHtml(log.message)}</div>
            </div>
        `;
    });
    
    document.getElementById('chainModalContent').innerHTML = html;
    document.getElementById('chainModal').classList.add('visible');
}

function navigateToLog(originalIndex, sectionName, pageNumber) {
    closeChainModal();
    
    const logsTab = document.querySelector('.tab[data-tab="logs"]');
    if (!logsTab.classList.contains('active')) {
        logsTab.click();
    }
    
    if (pageNumber && pageNumber >= 1) {
        currentPage = pageNumber;
        displayLogs();
    }
    
    if (collapsedSections.has(sectionName)) {
        collapsedSections.delete(sectionName);
        displayLogs();
    }
    
    setTimeout(() => {
        const logElement = document.getElementById(`log-${originalIndex}`);
        if (logElement) {
            logElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
            logElement.classList.add('highlighted');
            setTimeout(() => logElement.classList.remove('highlighted'), 1500);
        }
    }, 300);
}

function closeChainModal(event) {
    if (!event || event.target.id === 'chainModal') {
        document.getElementById('chainModal').classList.remove('visible');
    }
}

function closeGanttDetailModal(event) {
    if (!event || event.target.id === 'ganttDetailModal') {
        document.getElementById('ganttDetailModal').classList.remove('visible');
    }
}

// ==================== GANTT CHART ====================

function zoomGantt(delta) {
    const zoomFactors = [0.1, 0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 3.0, 5.0, 10.0, 25.0, 50.0, 100.0];
    let currentIdx = zoomFactors.findIndex(f => Math.abs(f - ganttZoom) < 0.01);
    
    if (currentIdx === -1) {
        currentIdx = zoomFactors.findIndex(f => f >= ganttZoom);
    }
    
    currentIdx += delta;
    currentIdx = Math.max(0, Math.min(zoomFactors.length - 1, currentIdx));
    
    const oldZoom = ganttZoom;
    ganttZoom = zoomFactors[currentIdx];
    document.getElementById('zoomLevel').textContent = `${ganttZoom}x`;
    
    const chartContainer = document.getElementById('ganttChart');
    if (chartContainer && chartContainer.scrollLeft !== undefined) {
        ganttScrollPos.left = chartContainer.scrollLeft;
        ganttScrollPos.top = chartContainer.scrollTop;
        
        const centerRatioX = (ganttScrollPos.left + chartContainer.clientWidth / 2) / chartContainer.scrollWidth;
        
        if (ganttData) {
            renderGanttChart();
            
            requestAnimationFrame(() => {
                const newScrollWidth = chartContainer.scrollWidth;
                const newScrollLeft = (centerRatioX * newScrollWidth) - (chartContainer.clientWidth / 2);
                
                chartContainer.scrollLeft = Math.max(0, newScrollLeft);
                chartContainer.scrollTop = ganttScrollPos.top;
            });
        }
    } else if (ganttData) {
        renderGanttChart();
    }
}

async function loadGanttData(fileId) {
    showProgress('Loading timeline...');
    updateProgress(30, 'Fetching data...');
    
    try {
        const response = await fetch(`${API_BASE}/api/v1/gantt/${fileId}`);
        ganttData = await response.json();
        
        updateProgress(80, 'Rendering chart...');
        renderGanttChart();
        
        updateProgress(100, 'Done!');
        hideProgress(500);
    } catch (error) {
        console.error('Error loading Gantt data:', error);
        document.getElementById('ganttChart').innerHTML = '<div class="empty-state"><p>Error loading timeline data</p></div>';
        hideProgress(0);
    }
}

function renderGanttChart() {
    const chart = document.getElementById('ganttChart');
    
    if (!ganttData || !ganttData.requests || ganttData.requests.length === 0) {
        chart.innerHTML = '<div class="empty-state"><p>No requests found in this log file</p></div>';
        return;
    }

    const summary = ganttData.summary;
    const timeline = ganttData.timeline;
    const requests = ganttData.requests;

    document.getElementById('ganttSummary').innerHTML = `
        <div class="gantt-summary-item">
            <div class="gantt-summary-value">${summary.total_requests}</div>
            <div>Requests</div>
        </div>
        <div class="gantt-summary-item">
            <div class="gantt-summary-value">${summary.duration_seconds.toFixed(2)}s</div>
            <div>Duration</div>
        </div>
        <div class="gantt-summary-item">
            <div class="gantt-summary-value">${summary.parallel_max}</div>
            <div>Parallel</div>
        </div>
    `;

    const startTime = new Date(timeline.start);
    const maxEndTime = Math.max(...requests.map(r => new Date(r.end_time).getTime()));
    const paddingMs = (maxEndTime - startTime.getTime()) * 0.05;
    const endTime = new Date(maxEndTime + paddingMs);
    const durationMs = endTime - startTime;

    const baseMarkersCount = 10;
    const adjustedMarkersCount = Math.ceil(baseMarkersCount * ganttZoom);
    const timeStep = durationMs / adjustedMarkersCount;

    const timeMarkers = [];
    let currentMarkerTime = startTime.getTime();
    while (currentMarkerTime <= endTime.getTime()) {
        timeMarkers.push({
            time: new Date(currentMarkerTime),
            label: formatAbsoluteTimeWithMicros(new Date(currentMarkerTime))
        });
        currentMarkerTime += timeStep;
    }
    if (timeMarkers.length === 0 || timeMarkers[timeMarkers.length - 1].time < endTime) {
        timeMarkers.push({
            time: endTime,
            label: formatAbsoluteTimeWithMicros(endTime)
        });
    }

    let labelsHTML = '<div class="gantt-labels-header">Request (RPC)</div>';
    let timelineRowsHTML = '';
    let timelineHeaderHTML = '';

    timeMarkers.forEach(marker => {
        timelineHeaderHTML += `<div class="gantt-time-marker">${marker.label}</div>`;
    });

    const swimlaneGroups = {};
    requests.forEach(req => {
        const lane = req.swimlane || 0;
        if (!swimlaneGroups[lane]) {
            swimlaneGroups[lane] = [];
        }
        swimlaneGroups[lane].push(req);
    });

    Object.keys(swimlaneGroups).forEach(lane => {
        swimlaneGroups[lane].sort((a, b) => 
            new Date(a.start_time).getTime() - new Date(b.start_time).getTime()
        );
    });

    let isFirstInLane = true;
    Object.keys(swimlaneGroups).sort((a, b) => parseInt(a) - parseInt(b)).forEach((lane, laneIndex) => {
        const laneRequests = swimlaneGroups[lane];
        const laneColor = swimlaneColors[laneIndex % swimlaneColors.length];
        const swimlaneName = `Parallel Process ${parseInt(lane) + 1}`;

        labelsHTML += `
            <div class="gantt-label-row gantt-swimlane-header" style="background: #505052; color: white; height: 32px; min-height: 32px;">
                <span style="font-weight: 700;">#${parseInt(lane) + 1}</span>
                <span style="font-weight: 700;">${swimlaneName}</span>
            </div>
        `;
        
        timelineRowsHTML += `
            <div class="gantt-timeline-row gantt-swimlane-header" style="background: #505052; height: 32px; min-height: 32px;"></div>
        `;

        isFirstInLane = false;
        
        laneRequests.forEach((req, indexInLane) => {
            const rpcLabel = req.rpc || 'unknown';
            const rowBg = indexInLane % 2 === 0 ? '#fafafa' : '#f5f5f7';
            
            labelsHTML += `
                <div class="gantt-label-row" style="background: ${rowBg} !important;">
                    <div class="gantt-label-text" title="${req.req_id} - ${rpcLabel}">
                        ${rpcLabel}
                    </div>
                </div>
            `;

            const reqStart = new Date(req.start_time);
            const reqEnd = new Date(req.end_time);
            
            const leftPercent = ((reqStart - startTime) / durationMs) * 100;
            const widthPercent = Math.max(0.1, ((reqEnd - reqStart) / durationMs) * 100);

            const showText = widthPercent * ganttZoom > 3;

            const gridHTML = timeMarkers.map(() => '<div class="gantt-grid-line"></div>').join('');

            let connectionLineHTML = '';
            if (indexInLane < laneRequests.length - 1) {
                const nextReq = laneRequests[indexInLane + 1];
                const nextStart = new Date(nextReq.start_time);
                
                const connectionLeft = ((reqEnd - startTime) / durationMs) * 100;
                const connectionWidth = ((nextStart - reqEnd) / durationMs) * 100;
                
                const approxContainerWidth = 1500;
                const connectionWidthPx = (connectionWidth / 100) * approxContainerWidth * ganttZoom;
                
                if (connectionWidth > 0 && connectionWidthPx >= 10) {
                    const connectionColor = req.status === 'success' ? '#34c759' :
                                        req.status === 'error' ? '#ff3b30' :
                                        req.status === 'timeout' ? '#ff9500' :
                                        req.status === 'running' ? '#007aff' : '#8e8e93';
                    
                    connectionLineHTML = `
                        <div class="gantt-connection-line" style="
                            left: ${connectionLeft}%; 
                            width: ${connectionWidth}%;
                            background: ${connectionColor};
                        "></div>
                    `;
                }
            }

            timelineRowsHTML += `
                <div class="gantt-timeline-row">
                    <div class="gantt-timeline-grid">
                        ${gridHTML}
                    </div>
                    ${connectionLineHTML}
                    <div class="gantt-bar ${req.status}" 
                         style="left: ${leftPercent}%; width: ${widthPercent}%;"
                         onmouseenter="showGanttTooltip(event, ${JSON.stringify(req).replace(/"/g, '&quot;')})"
                         onmouseleave="hideGanttTooltip()"
                         onclick="showGanttDetail(${JSON.stringify(req).replace(/"/g, '&quot;')})">
                        ${showText ? `<span class="gantt-bar-label">${rpcLabel}</span>` : ''}
                        ${showText ? `<span class="gantt-bar-duration">${req.duration}s</span>` : ''}
                    </div>
                </div>
            `;
        });
    });

    chart.innerHTML = `
        <div class="gantt-grid">
            <div class="gantt-labels">
                ${labelsHTML}
            </div>
            <div class="gantt-timeline">
                <div class="gantt-timeline-header">
                    ${timelineHeaderHTML}
                </div>
                <div class="gantt-timeline-rows">
                    ${timelineRowsHTML}
                </div>
            </div>
        </div>
    `;
}

function showGanttDetail(request) {
    const html = `
        <div style="font-family: 'SF Mono', monospace; font-size: 12px; line-height: 1.8;">
            <div style="margin-bottom: 16px;">
                <div style="font-weight: 700; font-size: 16px; margin-bottom: 8px; color: #1d1d1f;">
                    ${request.rpc || 'Unknown RPC'}
                </div>
                <div style="color: #6e6e73; word-break: break-all;">
                    ${request.req_id}
                </div>
            </div>
            <table style="width: 100%; border-collapse: collapse;">
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">Status:</td>
                    <td style="padding: 8px 0; font-weight: 600; text-transform: uppercase;">${request.status}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">Duration:</td>
                    <td style="padding: 8px 0; font-weight: 600;">${request.duration}s</td>
                </tr>
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">Start:</td>
                    <td style="padding: 8px 0;">${formatAbsoluteTimeWithMicros(new Date(request.start_time))}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">End:</td>
                    <td style="padding: 8px 0;">${formatAbsoluteTimeWithMicros(new Date(request.end_time))}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">Logs:</td>
                    <td style="padding: 8px 0; font-weight: 600;">${request.log_count}</td>
                </tr>
                <tr style="border-bottom: 1px solid #e5e5e7;">
                    <td style="padding: 8px 0; color: #6e6e73;">Swimlane:</td>
                    <td style="padding: 8px 0; font-weight: 600;">#${request.swimlane + 1}</td>
                </tr>
                ${request.error_count > 0 ? `
                <tr>
                    <td style="padding: 8px 0; color: #6e6e73;">Errors:</td>
                    <td style="padding: 8px 0; font-weight: 600; color: #ff3b30;">${request.error_count}</td>
                </tr>
                ` : ''}
            </table>
        </div>
    `;
    
    document.getElementById('ganttDetailContent').innerHTML = html;
    document.getElementById('ganttDetailModal').classList.add('visible');
}

function showGanttTooltip(event, request) {
    const tooltip = document.getElementById('ganttTooltip');
    
    const html = `
        <div class="gantt-tooltip-title">${request.rpc || 'Unknown RPC'}</div>
        <div class="gantt-tooltip-row">
            <span class="gantt-tooltip-label">Request ID:</span>
            <span>${request.req_id.substring(0, 20)}...</span>
        </div>
        <div class="gantt-tooltip-row">
            <span class="gantt-tooltip-label">Status:</span>
            <span style="text-transform: uppercase; font-weight: 600;">${request.status}</span>
        </div>
        <div class="gantt-tooltip-row">
            <span class="gantt-tooltip-label">Duration:</span>
            <span>${request.duration}s</span>
        </div>
        <div class="gantt-tooltip-row">
            <span class="gantt-tooltip-label">Logs:</span>
            <span>${request.log_count}</span>
        </div>
        ${request.error_count > 0 ? `
        <div class="gantt-tooltip-row">
            <span class="gantt-tooltip-label">Errors:</span>
            <span style="color: #ff3b30; font-weight: 600;">${request.error_count}</span>
        </div>
        ` : ''}
    `;
    
    tooltip.innerHTML = html;
    tooltip.style.display = 'block';
    
    const rect = tooltip.getBoundingClientRect();
    let left = event.pageX + 10;
    let top = event.pageY + 10;
    
    if (left + rect.width > window.innerWidth) {
        left = event.pageX - rect.width - 10;
    }
    
    if (top + rect.height > window.innerHeight) {
        top = event.pageY - rect.height - 10;
    }
    
    tooltip.style.left = left + 'px';
    tooltip.style.top = top + 'px';
}

function hideGanttTooltip() {
    document.getElementById('ganttTooltip').style.display = 'none';
}

// ==================== MONITORING ====================

async function loadMonitoringData() {
    try {
        const response = await fetch(`${API_BASE}/api/v1/metrics`);
        const metrics = await response.json();

        document.getElementById('metricTotalFiles').textContent = metrics.total_files;
        document.getElementById('metricErrors').textContent = metrics.total_errors;
        document.getElementById('metricWarnings').textContent = metrics.total_warnings;
        document.getElementById('metricHealth').textContent = metrics.error_rate.toFixed(1) + '%';

        if (metricsChart) {
            metricsChart.destroy();
        }

        const ctx = document.getElementById('metricsChart').getContext('2d');
        metricsChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: Object.keys(metrics.files_by_date),
                datasets: [{
                    label: 'Files Uploaded',
                    data: Object.values(metrics.files_by_date),
                    backgroundColor: '#007aff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    } catch (error) {
        console.error('Error loading monitoring data:', error);
    }
}

// ==================== UTILITY FUNCTIONS ====================

function formatTimestampFull(ts) {
    try {
        const date = new Date(ts);
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        const hours = String(date.getHours()).padStart(2, '0');
        const minutes = String(date.getMinutes()).padStart(2, '0');
        const seconds = String(date.getSeconds()).padStart(2, '0');
        const ms = String(date.getMilliseconds()).padStart(3, '0');
        const us = '000';
        
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}${us}`;
    } catch {
        return ts;
    }
}

function formatAbsoluteTimeWithMicros(date) {
    const year = date.getFullYear();
    const month = String(date.getMonth() + 1).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const seconds = String(date.getSeconds()).padStart(2, '0');
    const ms = String(date.getMilliseconds()).padStart(3, '0');
    const us = '000';
    
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}.${ms}${us}`;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}