package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
)

// Daftar IP yang diizinkan mengakses
var allowedIPs = []string{
	"127.0.0.1",
	"192.168.1.100",
	"125.161.196.176",
	// Tambahkan IP lain sesuai kebutuhan
}

type LogEntry struct {
	Message json.RawMessage `json:"message"`
}

type AttackLog struct {
	SrcHost   string      `json:"src_host"`
	DstHost   string      `json:"dst_host"`
	SrcPort   interface{} `json:"src_port"` // bisa string atau int
	DstPort   interface{} `json:"dst_port"` // bisa string atau int
	Timestamp string      `json:"timestamp"`
	LocalTime string      `json:"local_time"`
	UTCTime   string      `json:"utc_time"`
}

type Stats struct {
	AttackerIPs    map[string]int
	TargetHosts    map[string]int
	TargetPorts    map[int]int
	TargetServices map[string]int
	mu             sync.RWMutex
}

var (
	clients   = make(map[chan string]bool)
	clientsMu sync.Mutex
	stats     = &Stats{
		AttackerIPs:    make(map[string]int),
		TargetHosts:    make(map[string]int),
		TargetPorts:    make(map[int]int),
		TargetServices: make(map[string]int),
	}
	// Map port ke service name
	portServiceMap = map[int]string{
		21:    "FTP",
		22:    "SSH",
		23:    "Telnet",
		25:    "SMTP",
		53:    "DNS",
		80:    "HTTP",
		110:   "POP3",
		143:   "IMAP",
		443:   "HTTPS",
		445:   "SMB",
		1433:  "MSSQL",
		3306:  "MySQL",
		3389:  "RDP",
		5432:  "PostgreSQL",
		5900:  "VNC",
		6379:  "Redis",
		8080:  "HTTP-Proxy",
		9200:  "Elasticsearch",
		27017: "MongoDB",
	}
)

// Middleware untuk IP whitelisting
func ipWhitelistMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Ambil IP dari request
		ip, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			http.Error(w, "Invalid IP address", http.StatusForbidden)
			return
		}

		// Cek apakah IP diizinkan
		allowed := false
		for _, allowedIP := range allowedIPs {
			if ip == allowedIP {
				allowed = true
				break
			}
		}

		if !allowed {
			log.Printf("Akses diblokir dari IP: %s", ip)
			http.Error(w, "Akses ditolak", http.StatusForbidden)
			return
		}

		next(w, r)
	}
}

// Broadcast log ke semua client yang terhubung
func broadcast(message string) {
	clientsMu.Lock()
	defer clientsMu.Unlock()

	for client := range clients {
		select {
		case client <- message:
		default:
			close(client)
			delete(clients, client)
		}
	}
}

// Helper function untuk convert port interface{} ke int
func getPortNumber(portInterface interface{}) int {
	if portInterface == nil {
		return 0
	}
	
	switch v := portInterface.(type) {
	case string:
		// Parse string ke int
		var port int
		fmt.Sscanf(v, "%d", &port)
		return port
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

// Membaca log secara real-time
func tailLog() {
	cmd := exec.Command("tail", "-f", "/var/tmp/opencanary.log")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatal("Error creating pipe:", err)
	}

	if err := cmd.Start(); err != nil {
		log.Fatal("Error starting tail command:", err)
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()

		// Parse JSON untuk formatting yang lebih baik
		var prettyJSON map[string]interface{}
		if err := json.Unmarshal([]byte(line), &prettyJSON); err == nil {
			// Update statistik
			var attackLog AttackLog
			if err := json.Unmarshal([]byte(line), &attackLog); err == nil {
				stats.mu.Lock()
				
				// Track attacker IP
				if attackLog.SrcHost != "" {
					stats.AttackerIPs[attackLog.SrcHost]++
					log.Printf("Tracked attacker IP: %s (total: %d)", attackLog.SrcHost, stats.AttackerIPs[attackLog.SrcHost])
				}
				
				// Track target host
				if attackLog.DstHost != "" {
					stats.TargetHosts[attackLog.DstHost]++
					log.Printf("Tracked target host: %s (total: %d)", attackLog.DstHost, stats.TargetHosts[attackLog.DstHost])
				}
				
				// Track target port/service
				dstPort := getPortNumber(attackLog.DstPort)
				if dstPort > 0 {
					stats.TargetPorts[dstPort]++
					
					// Map port ke service name
					serviceName := portServiceMap[dstPort]
					if serviceName == "" {
						serviceName = fmt.Sprintf("Port %d", dstPort)
					}
					stats.TargetServices[serviceName]++
					log.Printf("Tracked service: %s on port %d (total: %d)", serviceName, dstPort, stats.TargetServices[serviceName])
				} else {
					log.Printf("Port tidak terdeteksi dari: %v", attackLog.DstPort)
				}
				
				stats.mu.Unlock()
			}

			formatted, _ := json.MarshalIndent(prettyJSON, "", "  ")
			broadcast(string(formatted))
		} else {
			broadcast(line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Println("Error reading log:", err)
	}
}

// Handler untuk halaman utama
func indexHandler(w http.ResponseWriter, r *http.Request) {
	html := `
<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sistem Pemantauan Serangan</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: linear-gradient(135deg, #0f0c29 0%, #302b63 50%, #24243e 100%);
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        
        .header {
            text-align: center;
            margin-bottom: 30px;
            animation: fadeInDown 0.6s ease-out;
        }
        
        h1 {
            font-size: 2.5em;
            font-weight: 700;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
        }
        
        .status-badge {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 10px 20px;
            border-radius: 50px;
            font-size: 14px;
            font-weight: 500;
            transition: all 0.3s ease;
            animation: pulse 2s ease-in-out infinite;
        }
        
        .status-badge.connected {
            background: rgba(16, 185, 129, 0.2);
            border: 2px solid #10b981;
            color: #10b981;
        }
        
        .status-badge.disconnected {
            background: rgba(239, 68, 68, 0.2);
            border: 2px solid #ef4444;
            color: #ef4444;
        }
        
        .status-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            animation: blink 1.5s ease-in-out infinite;
        }
        
        .connected .status-dot {
            background: #10b981;
            box-shadow: 0 0 10px #10b981;
        }
        
        .disconnected .status-dot {
            background: #ef4444;
            box-shadow: 0 0 10px #ef4444;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
            animation: fadeInUp 0.8s ease-out;
        }
        
        .card {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 25px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 12px 40px rgba(0, 0, 0, 0.4);
            border-color: rgba(102, 126, 234, 0.5);
        }
        
        .card-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 2px solid rgba(255, 255, 255, 0.1);
        }
        
        .card-icon {
            font-size: 28px;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));
        }
        
        .card-title {
            font-size: 18px;
            font-weight: 600;
            color: #fff;
        }
        
        table {
            width: 100%;
            border-collapse: separate;
            border-spacing: 0 8px;
        }
        
        th {
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #9ca3af;
            padding: 10px;
            text-align: left;
        }
        
        tbody tr {
            background: rgba(255, 255, 255, 0.03);
            transition: all 0.3s ease;
        }
        
        tbody tr:hover {
            background: rgba(102, 126, 234, 0.1);
            transform: scale(1.02);
        }
        
        td {
            padding: 12px 10px;
            border: none;
        }
        
        tbody tr td:first-child {
            border-radius: 10px 0 0 10px;
        }
        
        tbody tr td:last-child {
            border-radius: 0 10px 10px 0;
        }
        
        .rank {
            font-weight: 700;
            font-size: 16px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }
        
        .ip-address, .service-name {
            font-family: 'Courier New', monospace;
            font-size: 13px;
            color: #e0e0e0;
        }
        
        .count {
            font-weight: 600;
            font-size: 16px;
            color: #10b981;
            text-align: right;
        }
        
        .log-section {
            animation: fadeInUp 1s ease-out;
        }
        
        .log-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 15px;
        }
        
        .log-title {
            font-size: 20px;
            font-weight: 600;
            color: #fff;
        }
        
        #log-container {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 20px;
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
        }
        
        #log-container::-webkit-scrollbar {
            width: 8px;
        }
        
        #log-container::-webkit-scrollbar-track {
            background: rgba(255, 255, 255, 0.05);
            border-radius: 10px;
        }
        
        #log-container::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
        }
        
        .log-entry {
            margin-bottom: 15px;
            padding: 15px;
            background: rgba(255, 255, 255, 0.03);
            border-left: 4px solid #667eea;
            border-radius: 8px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-wrap: break-word;
            transition: all 0.3s ease;
            animation: slideInRight 0.3s ease-out;
        }
        
        .log-entry:hover {
            background: rgba(102, 126, 234, 0.1);
            border-left-color: #764ba2;
            transform: translateX(5px);
        }
        
        .timestamp {
            color: #10b981;
            font-weight: 600;
            display: inline-block;
            margin-bottom: 5px;
        }
        
        .empty-state {
            text-align: center;
            padding: 30px;
            color: #6b7280;
            font-style: italic;
        }
        
        @keyframes fadeInDown {
            from {
                opacity: 0;
                transform: translateY(-30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes slideInRight {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.8;
            }
        }
        
        @keyframes blink {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.3;
            }
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            
            h1 {
                font-size: 1.8em;
            }
            
            .card {
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Sistem Pemantauan Serangan Keamanan</h1>
        <div id="status" class="status-badge disconnected">
            <div class="status-dot"></div>
            <span>Menghubungkan...</span>
        </div>
    </div>
    
    <div class="dashboard">
        <div class="card">
            <div class="card-header">
                <div class="card-icon">🚨</div>
                <div class="card-title">Top 10 IP Penyerang</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th>Alamat IP</th>
                        <th style="width: 80px; text-align: right;">Serangan</th>
                    </tr>
                </thead>
                <tbody id="attackers-body">
                    <tr><td colspan="3" class="empty-state">Memuat data...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-icon">🎯</div>
                <div class="card-title">Top 10 Target Diserang</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th>Host</th>
                        <th style="width: 80px; text-align: right;">Serangan</th>
                    </tr>
                </thead>
                <tbody id="targets-body">
                    <tr><td colspan="3" class="empty-state">Memuat data...</td></tr>
                </tbody>
            </table>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-icon">⚙️</div>
                <div class="card-title">Top 10 Layanan Diserang</div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th style="width: 50px;">#</th>
                        <th>Layanan/Port</th>
                        <th style="width: 80px; text-align: right;">Serangan</th>
                    </tr>
                </thead>
                <tbody id="services-body">
                    <tr><td colspan="3" class="empty-state">Memuat data...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="log-section">
        <div class="log-header">
            <div class="card-icon">📋</div>
            <div class="log-title">Log Real-time</div>
        </div>
        <div id="log-container"></div>
    </div>

    <script>
        const logContainer = document.getElementById('log-container');
        const statusDiv = document.getElementById('status');
        const statusText = statusDiv.querySelector('span');
        const eventSource = new EventSource('/stream');

        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }

        function updateStats() {
            fetch('/stats')
                .then(response => response.json())
                .then(data => {
                    // Update attackers table
                    const attackersBody = document.getElementById('attackers-body');
                    if (data.top_attackers && data.top_attackers.length > 0) {
                        attackersBody.innerHTML = data.top_attackers.map((item, index) => 
                            '<tr>' +
                            '<td class="rank">' + (index + 1) + '</td>' +
                            '<td class="ip-address">' + escapeHtml(item.name) + '</td>' +
                            '<td class="count">' + item.count.toLocaleString() + '</td>' +
                            '</tr>'
                        ).join('');
                    } else {
                        attackersBody.innerHTML = '<tr><td colspan="3" class="empty-state">Belum ada data</td></tr>';
                    }

                    // Update targets table
                    const targetsBody = document.getElementById('targets-body');
                    if (data.top_targets && data.top_targets.length > 0) {
                        targetsBody.innerHTML = data.top_targets.map((item, index) => 
                            '<tr>' +
                            '<td class="rank">' + (index + 1) + '</td>' +
                            '<td class="ip-address">' + escapeHtml(item.name) + '</td>' +
                            '<td class="count">' + item.count.toLocaleString() + '</td>' +
                            '</tr>'
                        ).join('');
                    } else {
                        targetsBody.innerHTML = '<tr><td colspan="3" class="empty-state">Belum ada data</td></tr>';
                    }

                    // Update services table
                    const servicesBody = document.getElementById('services-body');
                    if (data.top_services && data.top_services.length > 0) {
                        servicesBody.innerHTML = data.top_services.map((item, index) => 
                            '<tr>' +
                            '<td class="rank">' + (index + 1) + '</td>' +
                            '<td class="service-name">' + escapeHtml(item.name) + '</td>' +
                            '<td class="count">' + item.count.toLocaleString() + '</td>' +
                            '</tr>'
                        ).join('');
                    } else {
                        servicesBody.innerHTML = '<tr><td colspan="3" class="empty-state">Belum ada data</td></tr>';
                    }
                })
                .catch(error => console.error('Error fetching stats:', error));
        }

        // Update stats setiap 3 detik
        updateStats();
        setInterval(updateStats, 3000);

        eventSource.onopen = function() {
            statusDiv.className = 'status-badge connected';
            statusText.textContent = 'Terhubung';
        };

        eventSource.onmessage = function(event) {
            const logEntry = document.createElement('div');
            logEntry.className = 'log-entry';
            
            const now = new Date().toLocaleTimeString('id-ID');
            const logData = event.data;
            const escapedData = escapeHtml(logData);
            logEntry.innerHTML = '<div class="timestamp">[' + now + ']</div>' + escapedData;
            
            logContainer.insertBefore(logEntry, logContainer.firstChild);
            
            // Batasi jumlah log yang ditampilkan (maksimal 50 entry)
            while (logContainer.children.length > 50) {
                logContainer.removeChild(logContainer.lastChild);
            }
        };

        eventSource.onerror = function() {
            statusDiv.className = 'status-badge disconnected';
            statusText.textContent = 'Terputus';
        };
    </script>
</body>
</html>
`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

// Handler untuk streaming log menggunakan Server-Sent Events
func streamHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Buat channel untuk client ini
	messageChan := make(chan string)

	// Register client
	clientsMu.Lock()
	clients[messageChan] = true
	clientsMu.Unlock()

	// Cleanup saat client disconnect
	defer func() {
		clientsMu.Lock()
		delete(clients, messageChan)
		close(messageChan)
		clientsMu.Unlock()
	}()

	// Stream messages ke client
	for {
		select {
		case message := <-messageChan:
			// Encode multi-line data untuk SSE
			lines := strings.Split(message, "\n")
			for _, line := range lines {
				fmt.Fprintf(w, "data: %s\n", line)
			}
			fmt.Fprintf(w, "\n")
			w.(http.Flusher).Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// Handler untuk API statistik
func statsHandler(w http.ResponseWriter, r *http.Request) {
	stats.mu.RLock()
	defer stats.mu.RUnlock()

	type StatItem struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	type StatsResponse struct {
		TopAttackers []StatItem `json:"top_attackers"`
		TopTargets   []StatItem `json:"top_targets"`
		TopServices  []StatItem `json:"top_services"`
	}

	// Sort dan ambil top 10 attackers
	topAttackers := make([]StatItem, 0)
	for ip, count := range stats.AttackerIPs {
		topAttackers = append(topAttackers, StatItem{Name: ip, Count: count})
	}
	// Simple bubble sort untuk top 10
	for i := 0; i < len(topAttackers); i++ {
		for j := i + 1; j < len(topAttackers); j++ {
			if topAttackers[j].Count > topAttackers[i].Count {
				topAttackers[i], topAttackers[j] = topAttackers[j], topAttackers[i]
			}
		}
	}
	if len(topAttackers) > 10 {
		topAttackers = topAttackers[:10]
	}

	// Sort dan ambil top 10 targets
	topTargets := make([]StatItem, 0)
	for host, count := range stats.TargetHosts {
		topTargets = append(topTargets, StatItem{Name: host, Count: count})
	}
	for i := 0; i < len(topTargets); i++ {
		for j := i + 1; j < len(topTargets); j++ {
			if topTargets[j].Count > topTargets[i].Count {
				topTargets[i], topTargets[j] = topTargets[j], topTargets[i]
			}
		}
	}
	if len(topTargets) > 10 {
		topTargets = topTargets[:10]
	}

	// Sort dan ambil top 10 services
	topServices := make([]StatItem, 0)
	for service, count := range stats.TargetServices {
		topServices = append(topServices, StatItem{Name: service, Count: count})
	}
	for i := 0; i < len(topServices); i++ {
		for j := i + 1; j < len(topServices); j++ {
			if topServices[j].Count > topServices[i].Count {
				topServices[i], topServices[j] = topServices[j], topServices[i]
			}
		}
	}
	if len(topServices) > 10 {
		topServices = topServices[:10]
	}

	response := StatsResponse{
		TopAttackers: topAttackers,
		TopTargets:   topTargets,
		TopServices:  topServices,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func main() {
	// Mulai membaca log di background
	go tailLog()

	// Setup routes dengan IP whitelisting
	http.HandleFunc("/", ipWhitelistMiddleware(indexHandler))
	http.HandleFunc("/stream", ipWhitelistMiddleware(streamHandler))
	http.HandleFunc("/stats", ipWhitelistMiddleware(statsHandler))

	port := ":7080"
	log.Printf("Server dimulai di http://localhost%s", port)
	log.Printf("IP yang diizinkan: %v", allowedIPs)

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal("Server error:", err)
	}
}
