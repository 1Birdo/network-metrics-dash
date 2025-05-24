package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/disk"
	"github.com/shirou/gopsutil/host"
	"github.com/shirou/gopsutil/load"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/net"
)

const (
	apiKey      = "Api-Key From Dashboard"
	serverName  = "MyServer011"
	wsServerURL = "wss://localhost:443/ws"
	interval    = 5 * time.Second
)

type Metrics struct {
	CPUPercent    float64   `json:"cpu_percent"`
	MemoryPercent float64   `json:"memory_percent"`
	DiskPercent   float64   `json:"disk_percent"`
	Uptime        int64     `json:"uptime"`
	NetworkIn     float64   `json:"network_in"`
	NetworkOut    float64   `json:"network_out"`
	LoadAvg       []float64 `json:"load_avg"`
	DiskReadRate  float64   `json:"disk_read_rate"`
	DiskWriteRate float64   `json:"disk_write_rate"`
}

type Message struct {
	Type string  `json:"type"`
	Data Metrics `json:"data"`
}

type rateCalculator struct {
	prevNetIO   *net.IOCountersStat
	prevDiskIO  map[string]disk.IOCountersStat
	lastUpdated time.Time
}

func roundToTwoDecimals(value float64) float64 {
	return math.Round(value*100) / 100
}

func sanitizeFloat(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0.0
	}
	return value
}

func getSystemMetrics(rc *rateCalculator) (Metrics, error) {
	// CPU
	cpuPercent, err := cpu.Percent(interval, false)
	if err != nil {
		return Metrics{}, fmt.Errorf("cpu error: %w", err)
	}

	// Memory
	memStat, err := mem.VirtualMemory()
	if err != nil {
		return Metrics{}, fmt.Errorf("memory error: %w", err)
	}

	// Disk
	diskStat, err := disk.Usage("/")
	if err != nil {
		return Metrics{}, fmt.Errorf("disk error: %w", err)
	}

	// Host info
	hostStat, err := host.Info()
	if err != nil {
		return Metrics{}, fmt.Errorf("host info error: %w", err)
	}

	// Network
	netIO, err := net.IOCounters(false)
	if err != nil {
		return Metrics{}, fmt.Errorf("network error: %w", err)
	}

	// Load average
	loadAvg, err := load.Avg()
	if err != nil {
		return Metrics{}, fmt.Errorf("load avg error: %w", err)
	}

	// Calculate network rates
	var netIn, netOut float64
	if rc.prevNetIO != nil && len(netIO) > 0 {
		timeDiff := time.Since(rc.lastUpdated).Seconds()
		if timeDiff > 0 {
			netIn = float64(netIO[0].BytesRecv-rc.prevNetIO.BytesRecv) / timeDiff
			netOut = float64(netIO[0].BytesSent-rc.prevNetIO.BytesSent) / timeDiff
		}
	}

	// Calculate disk rates
	diskIO, _ := disk.IOCounters()
	var readRate, writeRate float64
	if rc.prevDiskIO != nil && diskIO != nil {
		for name, current := range diskIO {
			if prev, exists := rc.prevDiskIO[name]; exists {
				timeDiff := time.Since(rc.lastUpdated).Seconds()
				if timeDiff > 0 {
					readRate += float64(current.ReadBytes-prev.ReadBytes) / timeDiff
					writeRate += float64(current.WriteBytes-prev.WriteBytes) / timeDiff
				}
			}
		}
	}

	// Update previous values
	if len(netIO) > 0 {
		rc.prevNetIO = &netIO[0]
	}
	rc.prevDiskIO = diskIO
	rc.lastUpdated = time.Now()

	// Sanitize and convert values
	netIn = sanitizeFloat(netIn) / 1024 / 1024 // Convert to MB/s
	netOut = sanitizeFloat(netOut) / 1024 / 1024
	readRate = sanitizeFloat(readRate) / 1024 / 1024
	writeRate = sanitizeFloat(writeRate) / 1024 / 1024

	return Metrics{
		CPUPercent:    roundToTwoDecimals(sanitizeFloat(cpuPercent[0])),
		MemoryPercent: roundToTwoDecimals(sanitizeFloat(memStat.UsedPercent)),
		DiskPercent:   roundToTwoDecimals(sanitizeFloat(diskStat.UsedPercent)),
		Uptime:        int64(time.Now().Unix() - int64(hostStat.BootTime)),
		NetworkIn:     roundToTwoDecimals(netIn),
		NetworkOut:    roundToTwoDecimals(netOut),
		LoadAvg: []float64{
			roundToTwoDecimals(sanitizeFloat(loadAvg.Load1)),
			roundToTwoDecimals(sanitizeFloat(loadAvg.Load5)),
			roundToTwoDecimals(sanitizeFloat(loadAvg.Load15)),
		},
		DiskReadRate:  roundToTwoDecimals(readRate),
		DiskWriteRate: roundToTwoDecimals(writeRate),
	}, nil
}

func sendMetrics(ctx context.Context) {
	headers := map[string][]string{
		"x-api-key":     {apiKey},
		"x-server-name": {serverName},
		"user-agent":    {"SystemMonitor/1.0"},
	}

	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{
			MinVersion:         tls.VersionTLS13,
			InsecureSkipVerify: true,
		},
		HandshakeTimeout: 10 * time.Second,
	}

	rc := &rateCalculator{}
	retryDelay := 5 * time.Second
	maxRetryDelay := 300 * time.Second

	for {
		select {
		case <-ctx.Done():
			log.Println("Stopped by user")
			return
		default:
		}

		conn, resp, err := dialer.Dial(wsServerURL, headers)
		if err != nil {
			log.Printf("Connection failed: %v (retrying in %v)", err, retryDelay)
			time.Sleep(retryDelay)
			retryDelay = time.Duration(math.Min(float64(retryDelay)*1.5, float64(maxRetryDelay)))
			continue
		}
		defer conn.Close()

		log.Printf("Connected to %s (HTTP %d)", wsServerURL, resp.StatusCode)
		retryDelay = 5 * time.Second
		rc = &rateCalculator{}

		done := make(chan struct{})
		go func() {
			defer close(done)
			conn.SetReadDeadline(time.Now().Add(15 * time.Second))
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Printf("Read error: %v", err)
				return
			}
			log.Printf("Server ack: %s", msg)
		}()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-done:
				log.Println("Connection lost")
				return
			case <-ctx.Done():
				log.Println("Shutting down")
				return
			case <-ticker.C:
				metrics, err := getSystemMetrics(rc)
				if err != nil {
					log.Printf("Metrics error: %v", err)
					continue
				}

				msg, err := json.Marshal(Message{Type: "metrics", Data: metrics})
				if err != nil {
					log.Printf("JSON marshal error: %v", err)
					continue
				}

				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					log.Printf("Write error: %v", err)
					return
				}

				log.Printf("Sent metrics - CPU: %.2f%%, Mem: %.2f%%, Disk: %.2f%%, Load: %.2f",
					metrics.CPUPercent,
					metrics.MemoryPercent,
					metrics.DiskPercent,
					metrics.LoadAvg[1],
				)
			}
		}
	}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting metrics sender...")
	sendMetrics(ctx)
	log.Println("Metrics sender stopped")
}
