// Dashboard JavaScript functionality

let currentGuildId = '';
let selectedMessageId = null;
let trendsChart = null;
let actionsChart = null;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeEventListeners();
    loadGuildList();
    showPage('overview');
});

function initializeEventListeners() {
    // Navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const page = this.getAttribute('data-page');
            showPage(page);
        });
    });
    
    // Guild selector
    document.getElementById('guildSelect').addEventListener('change', function() {
        currentGuildId = this.value;
        if (currentGuildId) {
            refreshData();
        }
    });
    
    // Configuration form
    document.getElementById('configForm').addEventListener('submit', function(e) {
        e.preventDefault();
        saveConfiguration();
    });
}

function showPage(pageId) {
    // Hide all pages
    document.querySelectorAll('.page-content').forEach(page => {
        page.classList.add('d-none');
    });
    
    // Show selected page
    document.getElementById(pageId + 'Page').classList.remove('d-none');
    
    // Update navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`[data-page="${pageId}"]`).classList.add('active');
    
    // Update page title
    const titles = {
        'overview': 'Overview',
        'flagged-messages': 'Flagged Messages',
        'configuration': 'Configuration',
        'logs': 'System Logs'
    };
    document.getElementById('pageTitle').textContent = titles[pageId];
    
    // Load page-specific data
    if (currentGuildId) {
        switch (pageId) {
            case 'overview':
                loadOverviewData();
                break;
            case 'flagged-messages':
                loadFlaggedMessages();
                break;
            case 'configuration':
                loadConfiguration();
                break;
            case 'logs':
                loadLogs();
                break;
        }
    }
}

function refreshData() {
    if (!currentGuildId) return;
    
    const currentPage = document.querySelector('.nav-link.active').getAttribute('data-page');
    showPage(currentPage);
}

function loadGuildList() {
    // This would typically fetch from an API
    // For demo purposes, we'll use hardcoded values
    const guilds = [
        { id: '123456789', name: 'Demo Server 1' },
        { id: '987654321', name: 'Demo Server 2' }
    ];
    
    const select = document.getElementById('guildSelect');
    select.innerHTML = '<option value="">Choose a guild...</option>';
    
    guilds.forEach(guild => {
        const option = document.createElement('option');
        option.value = guild.id;
        option.textContent = guild.name;
        select.appendChild(option);
    });
}

async function loadOverviewData() {
    try {
        showLoading('overviewPage');
        
        const response = await fetch(`/api/guilds/${currentGuildId}/stats?days=30`);
        const data = await response.json();
        
        // Update stats cards
        document.getElementById('totalMessages').textContent = data.summary.total_flagged || 0;
        document.getElementById('scamCount').textContent = data.summary.scam_count || 0;
        document.getElementById('suspiciousCount').textContent = data.summary.suspicious_count || 0;
        document.getElementById('pendingCount').textContent = data.summary.pending_review || 0;
        
        // Update charts
        updateTrendsChart(data.daily_breakdown);
        updateActionsChart(data.moderator_actions);
        
        hideLoading('overviewPage');
    } catch (error) {
        console.error('Error loading overview data:', error);
        showError('Failed to load overview data');
        hideLoading('overviewPage');
    }
}

function updateTrendsChart(dailyData) {
    const ctx = document.getElementById('trendsChart').getContext('2d');
    
    if (trendsChart) {
        trendsChart.destroy();
    }
    
    const labels = dailyData.slice(-7).map(d => new Date(d.date).toLocaleDateString());
    const totalData = dailyData.slice(-7).map(d => d.total);
    const scamData = dailyData.slice(-7).map(d => d.scams);
    
    trendsChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Total Flagged',
                    data: totalData,
                    borderColor: 'rgb(75, 192, 192)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    tension: 0.1
                },
                {
                    label: 'Scams Detected',
                    data: scamData,
                    borderColor: 'rgb(255, 99, 132)',
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    tension: 0.1
                }
            ]
        },
        options: {
            responsive: true,
            scales: {
                y: {
                    beginAtZero: true
                }
            }
        }
    });
}

function updateActionsChart(actionsData) {
    const ctx = document.getElementById('actionsChart').getContext('2d');
    
    if (actionsChart) {
        actionsChart.destroy();
    }
    
    const labels = Object.keys(actionsData);
    const data = Object.values(actionsData);
    
    actionsChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels.map(label => label.replace('_', ' ').toUpperCase()),
            datasets: [{
                data: data,
                backgroundColor: [
                    '#28a745', // approve
                    '#dc3545', // delete_ban
                    '#ffc107', // warn
                    '#6c757d'  // ignore
                ]
            }]
        },
        options: {
            responsive: true
        }
    });
}

async function loadFlaggedMessages() {
    try {
        showLoading('flaggedMessagesPage');
        
        const status = document.getElementById('statusFilter').value;
        const params = new URLSearchParams();
        if (status) params.append('status', status);
        
        const response = await fetch(`/api/guilds/${currentGuildId}/flagged-messages?${params}`);
        const data = await response.json();
        
        renderMessages(data.messages);
        hideLoading('flaggedMessagesPage');
    } catch (error) {
        console.error('Error loading flagged messages:', error);
        showError('Failed to load flagged messages');
        hideLoading('flaggedMessagesPage');
    }
}

function renderMessages(messages) {
    const container = document.getElementById('messagesList');
    
    if (messages.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No flagged messages found.</div>';
        return;
    }
    
    container.innerHTML = messages.map(message => {
        const labelClass = {
            'scam': 'badge-scam',
            'suspicious': 'badge-suspicious',
            'not_scam': 'badge-not-scam'
        }[message.label] || 'bg-secondary';
        
        const statusClass = {
            'pending': 'warning',
            'reviewed': 'success',
            'approved': 'info',
            'deleted': 'danger'
        }[message.status] || 'secondary';
        
        return `
            <div class="card message-card mb-3">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <div>
                        <span class="badge ${labelClass}">${message.label.replace('_', ' ')}</span>
                        <span class="badge bg-${statusClass}">${message.status}</span>
                        <small class="text-muted ms-2">${new Date(message.created_at).toLocaleString()}</small>
                    </div>
                    <div class="confidence-bar position-relative" style="width: 100px;">
                        <div class="confidence-indicator" style="left: ${message.confidence * 100}%;"></div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-8">
                            <h6>Message Content:</h6>
                            <p class="text-muted">${escapeHtml(message.text.substring(0, 200))}${message.text.length > 200 ? '...' : ''}</p>
                            
                            ${message.ocr_text ? `
                                <h6>OCR Text:</h6>
                                <p class="text-muted small">${escapeHtml(message.ocr_text.substring(0, 150))}</p>
                            ` : ''}
                            
                            <div class="d-flex flex-wrap gap-1 mb-2">
                                ${message.indicator_tags.map(tag => `<span class="badge bg-light text-dark">${tag}</span>`).join('')}
                            </div>
                            
                            <small><strong>Reason:</strong> ${message.short_reason}</small>
                        </div>
                        <div class="col-md-4">
                            <p><strong>Confidence:</strong> ${(message.confidence * 100).toFixed(1)}%</p>
                            <p><strong>Author ID:</strong> ${message.author_id}</p>
                            <p><strong>Channel ID:</strong> ${message.channel_id}</p>
                            
                            ${message.status === 'pending' ? `
                                <button class="btn btn-primary btn-sm" onclick="openActionModal(${message.id})">
                                    <i class="fas fa-gavel me-1"></i>Take Action
                                </button>
                            ` : ''}
                            
                            ${message.moderator_actions.length > 0 ? `
                                <div class="mt-2">
                                    <small><strong>Actions:</strong></small>
                                    ${message.moderator_actions.map(action => `
                                        <div class="small text-muted">
                                            ${action.action} by ${action.moderator_id}
                                            ${action.reason ? `- ${action.reason}` : ''}
                                        </div>
                                    `).join('')}
                                </div>
                            ` : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

function openActionModal(messageId) {
    selectedMessageId = messageId;
    const modal = new bootstrap.Modal(document.getElementById('actionModal'));
    modal.show();
}

async function takeAction(action) {
    if (!selectedMessageId) return;
    
    const reason = document.getElementById('actionReason').value;
    const moderatorId = prompt('Enter your Discord User ID:'); // In production, this would come from authentication
    
    if (!moderatorId) return;
    
    try {
        const response = await fetch(`/api/flagged-messages/${selectedMessageId}/action?moderator_id=${moderatorId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                action: action,
                reason: reason || null
            })
        });
        
        if (response.ok) {
            showSuccess(`Action "${action}" taken successfully`);
            bootstrap.Modal.getInstance(document.getElementById('actionModal')).hide();
            loadFlaggedMessages(); // Refresh the list
        } else {
            const error = await response.json();
            showError(`Failed to take action: ${error.detail}`);
        }
    } catch (error) {
        console.error('Error taking action:', error);
        showError('Failed to take action');
    }
}

async function loadConfiguration() {
    try {
        showLoading('configurationPage');
        
        const response = await fetch(`/api/guilds/${currentGuildId}/config`);
        const config = await response.json();
        
        // Populate form fields
        document.getElementById('autoDeleteConfidence').value = config.auto_delete_confidence || 0.9;
        document.getElementById('flagThreshold').value = config.flag_threshold || 0.5;
        document.getElementById('modChannelId').value = config.mod_channel_id || '';
        document.getElementById('logChannelId').value = config.log_channel_id || '';
        document.getElementById('enableRules').checked = config.enable_rules !== false;
        document.getElementById('enableOcr').checked = config.enable_ocr !== false;
        document.getElementById('enableLlm').checked = config.enable_llm !== false;
        document.getElementById('retentionDays').value = config.retention_days || 30;
        
        hideLoading('configurationPage');
    } catch (error) {
        console.error('Error loading configuration:', error);
        showError('Failed to load configuration');
        hideLoading('configurationPage');
    }
}

async function saveConfiguration() {
    const moderatorId = prompt('Enter your Discord User ID:'); // In production, this would come from authentication
    if (!moderatorId) return;
    
    try {
        const configData = {
            auto_delete_confidence: parseFloat(document.getElementById('autoDeleteConfidence').value),
            flag_threshold: parseFloat(document.getElementById('flagThreshold').value),
            mod_channel_id: document.getElementById('modChannelId').value || null,
            log_channel_id: document.getElementById('logChannelId').value || null,
            enable_rules: document.getElementById('enableRules').checked,
            enable_ocr: document.getElementById('enableOcr').checked,
            enable_llm: document.getElementById('enableLlm').checked,
            retention_days: parseInt(document.getElementById('retentionDays').value)
        };
        
        const response = await fetch(`/api/guilds/${currentGuildId}/config?moderator_id=${moderatorId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(configData)
        });
        
        if (response.ok) {
            showSuccess('Configuration saved successfully');
        } else {
            const error = await response.json();
            showError(`Failed to save configuration: ${error.detail}`);
        }
    } catch (error) {
        console.error('Error saving configuration:', error);
        showError('Failed to save configuration');
    }
}

async function loadLogs() {
    try {
        showLoading('logsPage');
        
        const level = document.getElementById('logLevelFilter').value;
        const component = document.getElementById('componentFilter').value;
        
        const params = new URLSearchParams();
        if (level) params.append('level', level);
        if (component) params.append('component', component);
        
        const response = await fetch(`/api/guilds/${currentGuildId}/logs?${params}`);
        const data = await response.json();
        
        renderLogs(data.logs);
        hideLoading('logsPage');
    } catch (error) {
        console.error('Error loading logs:', error);
        showError('Failed to load logs');
        hideLoading('logsPage');
    }
}

function renderLogs(logs) {
    const container = document.getElementById('logsList');
    
    if (logs.length === 0) {
        container.innerHTML = '<div class="alert alert-info">No logs found.</div>';
        return;
    }
    
    container.innerHTML = `
        <div class="table-responsive">
            <table class="table table-striped">
                <thead>
                    <tr>
                        <th>Time</th>
                        <th>Level</th>
                        <th>Component</th>
                        <th>Message</th>
                        <th>User</th>
                    </tr>
                </thead>
                <tbody>
                    ${logs.map(log => {
                        const levelClass = {
                            'INFO': 'text-info',
                            'WARNING': 'text-warning',
                            'ERROR': 'text-danger',
                            'CRITICAL': 'text-danger fw-bold'
                        }[log.level] || '';
                        
                        return `
                            <tr>
                                <td><small>${new Date(log.created_at).toLocaleString()}</small></td>
                                <td><span class="${levelClass}">${log.level}</span></td>
                                <td><span class="badge bg-secondary">${log.component}</span></td>
                                <td>${escapeHtml(log.message)}</td>
                                <td>${log.user_id || '-'}</td>
                            </tr>
                        `;
                    }).join('')}
                </tbody>
            </table>
        </div>
    `;
}

// Utility functions
function showLoading(pageId) {
    const page = document.getElementById(pageId);
    const existingSpinner = page.querySelector('.loading-spinner');
    if (existingSpinner) return;
    
    const spinner = document.createElement('div');
    spinner.className = 'loading-spinner text-center p-4';
    spinner.innerHTML = '<div class="spinner-border" role="status"><span class="visually-hidden">Loading...</span></div>';
    page.appendChild(spinner);
}

function hideLoading(pageId) {
    const page = document.getElementById(pageId);
    const spinner = page.querySelector('.loading-spinner');
    if (spinner) {
        spinner.remove();
    }
}

function showSuccess(message) {
    showAlert(message, 'success');
}

function showError(message) {
    showAlert(message, 'danger');
}

function showAlert(message, type) {
    const alertHtml = `
        <div class="alert alert-${type} alert-dismissible fade show" role="alert">
            ${message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
    `;
    
    const alertContainer = document.getElementById('pageTitle').parentNode;
    alertContainer.insertAdjacentHTML('afterend', alertHtml);
    
    // Auto-dismiss after 5 seconds
    setTimeout(() => {
        const alert = alertContainer.nextElementSibling;
        if (alert && alert.classList.contains('alert')) {
            bootstrap.Alert.getOrCreateInstance(alert).close();
        }
    }, 5000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
