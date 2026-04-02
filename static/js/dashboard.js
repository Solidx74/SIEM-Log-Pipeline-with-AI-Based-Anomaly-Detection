// Connect to SocketIO
var socket = io();

// Track last alert count for animation
let lastAlertCount = 0;

// Function to fetch initial data and update charts
function fetchStats() {
    $.get('/api/stats', function(data) {
        $('#alert-count').text(data.alert_count);
        $('#anomaly-count').text(data.anomaly_count);
        $('#log-count').text(data.log_count);
        let lastTime = data.last_anomaly ? new Date(data.last_anomaly).toLocaleString() : 'Never';
        $('#last-anomaly').text(lastTime);
        
        // Check if new alerts arrived
        if (data.alert_count > lastAlertCount) {
            $('#alert-count').css('animation', 'pulse 0.5s');
            setTimeout(() => {
                $('#alert-count').css('animation', '');
            }, 500);
        }
        lastAlertCount = data.alert_count;
    }).fail(function(error) {
        console.error('Error fetching stats:', error);
    });
}

function fetchAlerts() {
    $.get('/api/alerts', function(data) {
        var tbody = $('#alerts-table tbody');
        tbody.empty();
        if (data.length === 0) {
            tbody.append('<tr class="loading-row"><td colspan="4">No alerts detected. System operational.</td></tr>');
            return;
        }
        data.forEach(function(alert, index) {
            let riskColor = alert.anomaly_score < -0.3 ? 'risk-critical' : 
                           alert.anomaly_score < -0.1 ? 'risk-high' : 'risk-medium';
            let rowClass = index === 0 ? 'new-alert-row' : '';
            tbody.append(`
                <tr class="${rowClass}">
                    <td>${new Date(alert.timestamp).toLocaleString()}</td>
                    <td><span class="badge" style="background: rgba(0,242,255,0.1);">${escapeHtml(alert.algorithm)}</span></td>
                    <td class="${riskColor}">${alert.anomaly_score.toFixed(4)}</td>
                    <td><span class="entity-id">${escapeHtml(alert.log_id)}</span></td>
                </tr>
            `);
        });
        
        // Remove animation class after animation completes
        setTimeout(() => {
            $('.new-alert-row').removeClass('new-alert-row');
        }, 1000);
    }).fail(function(error) {
        console.error('Error fetching alerts:', error);
    });
}

function fetchAnomalies() {
    $.get('/api/anomalies', function(data) {
        var tbody = $('#anomalies-table tbody');
        tbody.empty();
        if (data.length === 0) {
            tbody.append('<tr class="loading-row"><td colspan="4">No anomalies detected. Waiting for data...</td></tr>');
            return;
        }
        data.forEach(function(anomaly) {
            let scoreColor = anomaly.anomaly_score < -0.3 ? 'risk-critical' : 'risk-high';
            tbody.append(`
                <tr>
                    <td>${new Date(anomaly.timestamp).toLocaleString()}</td>
                    <td><span class="badge">${escapeHtml(anomaly.algorithm)}</span></td>
                    <td class="${scoreColor}">${anomaly.anomaly_score.toFixed(4)}</td>
                    <td style="max-width: 400px; overflow-x: auto; white-space: nowrap;">${escapeHtml(anomaly.raw_line.substring(0, 100))}${anomaly.raw_line.length > 100 ? '...' : ''}</td>
                </tr>
            `);
        });
    }).fail(function(error) {
        console.error('Error fetching anomalies:', error);
    });
}

// Page-specific data loading functions
function loadLiveLogs() {
    $.get('/api/logs', function(data) {
        var tbody = $('#logs-table tbody');
        tbody.empty();
        if (data.length === 0) {
            tbody.append('<tr class="loading-row"><td colspan="4">No logs available...</td></tr>');
            return;
        }
        data.forEach(function(log) {
            tbody.append(`
                <tr>
                    <td>${new Date(log.timestamp).toLocaleString()}</td>
                    <td>${escapeHtml(log.service || 'unknown')}</td>
                    <td>${escapeHtml(log.hostname || 'localhost')}</td>
                    <td style="max-width: 500px; overflow-x: auto;">${escapeHtml(log.message || log.raw_line || '')}</td>
                </tr>
            `);
        });
    }).fail(function() {
        $('#logs-table tbody').html('<tr class="loading-row"><td colspan="4">Error loading logs. Make sure log files exist.</td></tr>');
    });
}

function loadThreatsPage() {
    $.get('/api/anomalies', function(data) {
        var tbody = $('#anomalies-detailed-table tbody');
        tbody.empty();
        if (data.length === 0) {
            tbody.append('<tr class="loading-row"><td colspan="5">No threats detected. System secure.</td></tr>');
            return;
        }
        data.forEach(function(anomaly) {
            let riskLevel = anomaly.anomaly_score < -0.3 ? 'CRITICAL' : 'HIGH';
            let riskColor = anomaly.anomaly_score < -0.3 ? '#ff3e3e' : '#ffaa00';
            tbody.append(`
                <tr>
                    <td>${new Date(anomaly.timestamp).toLocaleString()}</td>
                    <td><span class="badge">${escapeHtml(anomaly.algorithm)}</span></td>
                    <td style="color: ${riskColor}; font-weight: bold;">${anomaly.anomaly_score.toFixed(4)}</td>
                    <td style="max-width: 400px; overflow-x: auto; white-space: nowrap;">${escapeHtml(anomaly.raw_line.substring(0, 150))}${anomaly.raw_line.length > 150 ? '...' : ''}</td>
                    <td style="color: ${riskColor};">${riskLevel}</td>
                </tr>
            `);
        });
    }).fail(function() {
        $('#anomalies-detailed-table tbody').html('<tr class="loading-row"><td colspan="5">Error loading anomalies.</td></tr>');
    });
}

function loadConfigPage() {
    $.get('/api/config', function(data) {
        $('#config-algorithm').text(data.algorithm || 'Isolation Forest');
        $('#config-contamination').text(data.contamination || '0.1');
        $('#config-batch-size').text(data.batch_size || '100');
        $('#raw-logs-path').text(data.raw_logs_path || 'logs/raw_logs.log');
        $('#parsed-logs-path').text(data.parsed_logs_path || 'logs/logs_parsed.json');
        $('#features-path').text(data.features_path || 'logs/logs_features.jsonl');
        $('#alerts-path').text(data.alerts_path || 'alerts.jsonl');
        $('#collector-status').text('Running').addClass('active');
        $('#parser-status').text('Active').addClass('active');
        $('#feature-status').text('Active').addClass('active');
        $('#detector-status').text('Running').addClass('active');
    }).fail(function() {
        console.log('Config API not available yet');
        // Set default values if API fails
        $('#config-algorithm').text('Isolation Forest');
        $('#config-contamination').text('0.1');
        $('#config-batch-size').text('100');
    });
}

function loadCharts() {
    // Anomaly Trend
    $.get('/api/charts/anomaly_trend', function(data) {
        try {
            var fig = JSON.parse(data);
            Plotly.newPlot('anomaly-trend', fig.data, fig.layout, {displayModeBar: false, responsive: true});
        } catch(e) {
            console.error('Error parsing anomaly trend data:', e);
        }
    }).fail(function(error) {
        console.error('Error loading anomaly trend chart:', error);
    });
    
    // Log Volume
    $.get('/api/charts/log_volume', function(data) {
        try {
            var fig = JSON.parse(data);
            Plotly.newPlot('log-volume', fig.data, fig.layout, {displayModeBar: false, responsive: true});
        } catch(e) {
            console.error('Error parsing log volume data:', e);
        }
    }).fail(function(error) {
        console.error('Error loading log volume chart:', error);
    });
    
    // Alert Types
    $.get('/api/charts/alert_types', function(data) {
        try {
            var fig = JSON.parse(data);
            Plotly.newPlot('alert-types', fig.data, fig.layout, {displayModeBar: false, responsive: true});
        } catch(e) {
            console.error('Error parsing alert types data:', e);
        }
    }).fail(function(error) {
        console.error('Error loading alert types chart:', error);
    });
}

// Helper function to escape HTML
function escapeHtml(text) {
    if (!text) return '';
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(text));
    return div.innerHTML;
}

// Export function for alerts
window.exportAlerts = function() {
    let csv = [];
    let rows = document.querySelectorAll('#alerts-table tr');
    for (let i = 0; i < rows.length; i++) {
        let row = [], cols = rows[i].querySelectorAll('td, th');
        for (let j = 0; j < cols.length; j++) {
            row.push('"' + cols[j].innerText.replace(/"/g, '""') + '"');
        }
        csv.push(row.join(','));
    }
    let blob = new Blob([csv.join('\n')], {type: 'text/csv'});
    let link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `sentinel_alerts_${new Date().toISOString().slice(0,19).replace(/:/g, '-')}.csv`;
    link.click();
};

window.refreshData = function() {
    location.reload();
};

// SocketIO events
socket.on('connect', function() {
    console.log('[SENTINEL] Connected to SIEM engine');
    $('#alert-count').css('border-color', 'var(--accent-green)');
});

socket.on('disconnect', function() {
    console.log('[SENTINEL] Disconnected from SIEM engine');
    $('#alert-count').css('border-color', 'var(--accent-red)');
});

socket.on('stats_update', function(data) {
    $('#alert-count').text(data.alert_count);
    $('#anomaly-count').text(data.anomaly_count);
    $('#log-count').text(data.log_count);
    $('#last-anomaly').text(data.last_anomaly ? new Date(data.last_anomaly).toLocaleString() : 'Never');
});

socket.on('new_alert', function(data) {
    console.log('[SENTINEL] New threat detected!');
    // Refresh all data
    fetchAlerts();
    loadCharts();
    fetchAnomalies();
    fetchStats();
    
    // Flash effect for new alert
    $('.alert-tile').css('animation', 'pulse 0.5s');
    setTimeout(() => {
        $('.alert-tile').css('animation', '');
    }, 500);
});

// Navigation handling
$(document).ready(function() {
    // Initial load
    fetchStats();
    fetchAlerts();
    fetchAnomalies();
    loadCharts();
    
    // Set up navigation click handlers
    $('.nav-item').click(function() {
        const page = $(this).data('page');
        
        // Update active state in sidebar
        $('.nav-item').removeClass('active');
        $(this).addClass('active');
        
        // Hide all pages
        $('.page-content').removeClass('active-page');
        
        // Show selected page
        $(`#${page}-page`).addClass('active-page');
        
        // Load page-specific data
        if (page === 'live-logs') {
            loadLiveLogs();
        } else if (page === 'threats') {
            loadThreatsPage();
        } else if (page === 'config') {
            loadConfigPage();
        }
    });
    
    // Auto-refresh every 10 seconds (fallback for WebSocket)
    setInterval(function() {
        fetchStats();
        fetchAlerts();
        fetchAnomalies();
        loadCharts();
        
        // Also refresh page-specific data if on those pages
        const activePage = $('.page-content.active-page').attr('id');
        if (activePage === 'live-logs-page') {
            loadLiveLogs();
        } else if (activePage === 'threats-page') {
            loadThreatsPage();
        }
    }, 10000);
});

// Add CSS animation for new alerts
$('<style>')
    .prop('type', 'text/css')
    .html(`
        @keyframes alertFlash {
            0% { background-color: transparent; }
            50% { background-color: rgba(255, 62, 62, 0.2); }
            100% { background-color: transparent; }
        }
        .new-alert-row {
            animation: alertFlash 1s ease-in-out;
        }
    `)
    .appendTo('head');