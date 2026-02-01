/**
 * Mailwarden Web Interface - Frontend JavaScript
 * Pure vanilla JS, no dependencies
 */

// State
let ws = null;
let autoScroll = true;
let logLevelFilter = 'all';

// DOM Elements
const elements = {
    statusDot: document.getElementById('status-indicator'),
    statusText: document.getElementById('status-text'),
    themeToggle: document.getElementById('theme-toggle'),
    logOutput: document.getElementById('log-output'),
    logLevelFilter: document.getElementById('log-level-filter'),
    clearLogs: document.getElementById('clear-logs'),
    scrollBottom: document.getElementById('scroll-bottom'),
    configTextarea: document.getElementById('config-textarea'),
    configStatus: document.getElementById('config-status'),
    reloadConfig: document.getElementById('reload-config'),
    saveConfig: document.getElementById('save-config'),
    refreshStatus: document.getElementById('refresh-status'),
};

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    initTheme();
    initTabs();
    initWebSocket();
    initEventListeners();
    loadConfig();
    loadStatus();
});

// Theme Management
function initTheme() {
    const savedTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', savedTheme);
    updateThemeButton(savedTheme);
}

function toggleTheme() {
    const current = document.documentElement.getAttribute('data-theme');
    const next = current === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', next);
    localStorage.setItem('theme', next);
    updateThemeButton(next);
}

function updateThemeButton(theme) {
    elements.themeToggle.textContent = theme === 'dark' ? '☀️' : '🌙';
}

// Tab Navigation
function initTabs() {
    document.querySelectorAll('.nav-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.dataset.tab;
            
            // Update nav buttons
            document.querySelectorAll('.nav-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            
            // Update tab content
            document.querySelectorAll('.tab-content').forEach(tab => tab.classList.remove('active'));
            document.getElementById(`tab-${tabId}`).classList.add('active');
        });
    });
}

// WebSocket Connection
function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/logs`;
    
    updateConnectionStatus('connecting');
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        updateConnectionStatus('connected');
        console.log('WebSocket connected');
    };
    
    ws.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleWebSocketMessage(data);
        } catch (e) {
            console.error('WebSocket message parse error:', e);
        }
    };
    
    ws.onclose = () => {
        updateConnectionStatus('disconnected');
        console.log('WebSocket disconnected, reconnecting in 3s...');
        setTimeout(initWebSocket, 3000);
    };
    
    ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        updateConnectionStatus('disconnected');
    };
    
    // Keepalive ping
    setInterval(() => {
        if (ws && ws.readyState === WebSocket.OPEN) {
            ws.send('ping');
        }
    }, 25000);
}

function updateConnectionStatus(status) {
    elements.statusDot.className = 'status-dot';
    
    switch (status) {
        case 'connected':
            elements.statusDot.classList.add('connected');
            elements.statusText.textContent = 'Connected';
            break;
        case 'disconnected':
            elements.statusDot.classList.add('disconnected');
            elements.statusText.textContent = 'Disconnected';
            break;
        case 'connecting':
            elements.statusDot.classList.add('connecting');
            elements.statusText.textContent = 'Connecting...';
            break;
    }
}

function handleWebSocketMessage(data) {
    switch (data.type) {
        case 'history':
            // Initial log history
            data.data.forEach(log => addLogEntry(log));
            scrollToBottom();
            break;
        case 'log':
            // New log entry
            addLogEntry(data.data);
            if (autoScroll) scrollToBottom();
            break;
        case 'keepalive':
            // Server keepalive, ignore
            break;
    }
}

// Log Management
function addLogEntry(log) {
    // Check filter
    if (logLevelFilter !== 'all' && log.level !== logLevelFilter) {
        return;
    }
    
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `
        <span class="log-time">${formatTime(log.timestamp)}</span>
        <span class="log-level ${log.level}">${log.level}</span>
        <span class="log-logger">${log.logger || 'root'}</span>
        <span class="log-message">${escapeHtml(log.message)}</span>
    `;
    
    elements.logOutput.appendChild(entry);
    
    // Limit log entries to prevent memory issues
    while (elements.logOutput.children.length > 500) {
        elements.logOutput.removeChild(elements.logOutput.firstChild);
    }
}

function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleTimeString('nl-NL', { 
        hour: '2-digit', 
        minute: '2-digit', 
        second: '2-digit' 
    });
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

function scrollToBottom() {
    elements.logOutput.scrollTop = elements.logOutput.scrollHeight;
}

function clearLogs() {
    elements.logOutput.innerHTML = '';
}

// Configuration Management
async function loadConfig() {
    try {
        const response = await fetch('/api/config/raw');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        elements.configTextarea.value = data.content;
        showConfigStatus('Configuration loaded', 'success');
    } catch (error) {
        console.error('Failed to load config:', error);
        showConfigStatus(`Failed to load: ${error.message}`, 'error');
    }
}

async function saveConfig() {
    try {
        const content = elements.configTextarea.value;
        
        const response = await fetch('/api/config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ content })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.detail || 'Save failed');
        }
        
        showConfigStatus('Configuration saved successfully!', 'success');
    } catch (error) {
        console.error('Failed to save config:', error);
        showConfigStatus(`Failed to save: ${error.message}`, 'error');
    }
}

function showConfigStatus(message, type) {
    elements.configStatus.textContent = message;
    elements.configStatus.className = `config-status ${type}`;
    
    // Auto-clear after 5 seconds
    setTimeout(() => {
        elements.configStatus.textContent = '';
        elements.configStatus.className = 'config-status';
    }, 5000);
}

// Status Management
async function loadStatus() {
    try {
        const response = await fetch('/api/status');
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        
        const data = await response.json();
        
        document.getElementById('stat-status').textContent = data.status || '-';
        document.getElementById('stat-config').textContent = data.config_loaded ? '✓ Yes' : '✗ No';
        document.getElementById('stat-config-path').textContent = data.config_path || '-';
        document.getElementById('stat-clients').textContent = data.connected_clients || '0';
        document.getElementById('stat-buffer').textContent = `${data.log_buffer_size || 0} entries`;
    } catch (error) {
        console.error('Failed to load status:', error);
    }
}

// Event Listeners
function initEventListeners() {
    // Theme toggle
    elements.themeToggle.addEventListener('click', toggleTheme);
    
    // Log controls
    elements.logLevelFilter.addEventListener('change', (e) => {
        logLevelFilter = e.target.value;
        // Re-filter would require storing all logs, for now just affects new logs
    });
    
    elements.clearLogs.addEventListener('click', clearLogs);
    
    elements.scrollBottom.addEventListener('click', () => {
        autoScroll = !autoScroll;
        elements.scrollBottom.textContent = autoScroll ? '↓ Auto-scroll' : '⏸ Paused';
        if (autoScroll) scrollToBottom();
    });
    
    // Config controls
    elements.reloadConfig.addEventListener('click', loadConfig);
    elements.saveConfig.addEventListener('click', saveConfig);
    
    // Status refresh
    elements.refreshStatus.addEventListener('click', loadStatus);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        // Ctrl+S to save config
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            if (document.getElementById('tab-config').classList.contains('active')) {
                saveConfig();
            }
        }
    });
}
