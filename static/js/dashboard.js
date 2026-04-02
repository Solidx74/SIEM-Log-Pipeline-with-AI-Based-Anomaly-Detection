// Connect to SocketIO
var socket = io();

// Function to fetch initial data and update charts
function fetchStats() {
    $.get('/api/stats', function(data) {
        $('#alert-count').text(data.alert_count);
        $('#anomaly-count').text(data.anomaly_count);
        $('#log-count').text(data.log_count);
        $('#last-anomaly').text(data.last_anomaly ? new Date(data.last_anomaly).toLocaleString() : 'Never');
    });
}

function fetchAlerts() {
    $.get('/api/alerts', function(data) {
        var tbody = $('#alerts-table tbody');
        tbody.empty();
        data.forEach(function(alert) {
            tbody.append(`
                <tr>
                    <td>${new Date(alert.timestamp).toLocaleString()}</td>
                    <td>${alert.algorithm}</td>
                    <td>${alert.anomaly_score.toFixed(4)}</td>
                    <td>${alert.log_id}</td>
                </tr>
            `);
        });
    });
}

function fetchAnomalies() {
    $.get('/api/anomalies', function(data) {
        var tbody = $('#anomalies-table tbody');
        tbody.empty();
        data.forEach(function(anomaly) {
            tbody.append(`
                <tr>
                    <td>${new Date(anomaly.timestamp).toLocaleString()}</td>
                    <td>${anomaly.algorithm}</td>
                    <td>${anomaly.anomaly_score.toFixed(4)}</td>
                    <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${anomaly.raw_line}</td>
                </tr>
            `);
        });
    });
}

function loadCharts() {
    // Anomaly Trend
    $.get('/api/charts/anomaly_trend', function(data) {
        var fig = JSON.parse(data);
        Plotly.newPlot('anomaly-trend', fig.data, fig.layout);
    });
    // Log Volume
    $.get('/api/charts/log_volume', function(data) {
        var fig = JSON.parse(data);
        Plotly.newPlot('log-volume', fig.data, fig.layout);
    });
    // Alert Types
    $.get('/api/charts/alert_types', function(data) {
        var fig = JSON.parse(data);
        Plotly.newPlot('alert-types', fig.data, fig.layout);
    });
}

// SocketIO events
socket.on('connect', function() {
    console.log('Connected to server');
});

socket.on('stats_update', function(data) {
    $('#alert-count').text(data.alert_count);
    $('#anomaly-count').text(data.anomaly_count);
    $('#log-count').text(data.log_count);
    $('#last-anomaly').text(data.last_anomaly ? new Date(data.last_anomaly).toLocaleString() : 'Never');
});

socket.on('new_alert', function(data) {
    // Refresh alerts table and charts when new alert comes
    fetchAlerts();
    loadCharts();  // reload charts to show new data
});

// Initial load
fetchStats();
fetchAlerts();
fetchAnomalies();
loadCharts();

// Auto-refresh every 10 seconds (as backup)
setInterval(function() {
    fetchStats();
    fetchAlerts();
    fetchAnomalies();
    loadCharts();
}, 10000);