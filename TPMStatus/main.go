/*
Author: Christopher Bleakley
Email: chris@io-comms.co.uk
Date: 15-01-2025
Description: This tool collects device information (TPM Details) and stores it in a database.
Version: 1.1.2
*/

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	_ "github.com/denisenkom/go-mssqldb"
)

// DBConfig holds the database connection parameters
type DBConfig struct {
	Server   string
	Port     int
	User     string
	Password string
	Database string
}

type DeviceInfo struct {
	MACAddress     string
	SSE42          bool
	TPMEnabled     bool
	HighestVersion float64
	TotalMemory    int
}

type TpmDetails struct {
	Enabled        bool
	HighestVersion float64
}

var (
	db      *sql.DB
	Version = "1.1.2"
)

var kernel32 = syscall.NewLazyDLL("kernel32.dll")
var procIsProcessorFeaturePresent = kernel32.NewProc("IsProcessorFeaturePresent")
var procGlobalMemoryStatusEx = kernel32.NewProc("GlobalMemoryStatusEx")

const (
	FEATURE_SSE42 = 0x00000026
)

type MEMORYSTATUSEX struct {
	Length             uint32
	MemoryLoad         uint32
	TotalPhys          uint64
	AvailPhys          uint64
	TotalPageFile      uint64
	AvailPageFile      uint64
	TotalVirtual       uint64
	AvailVirtual       uint64
	SuiteMask          uint32
	ProcessorAffinity  uint32
}

func (c *DBConfig) ConnectionString() string {
	return fmt.Sprintf("server=%s;port=%d;user id=%s;password=%s;database=%s",
		c.Server, c.Port, c.User, c.Password, c.Database)
}

func main() {
	config := DBConfig{
		Server: "address",
		Port: 1433,
		User: "user",
		Password: "password",
		Database: "DeviceInfo",
	}

	connStr := config.ConnectionString()
	
	var err error
	db, err = sql.Open("sqlserver", connStr)
	if err != nil {
		log.Fatalf("Error opening database: %v", err)
	}
	defer db.Close()

	// Collect device information and store in the database
	deviceInfo, err := getDeviceInfo()
	if err != nil {
		log.Fatalf("Error collecting device info: %v", err)
	}
	err = upsertDeviceInfo(deviceInfo)
	if err != nil {
		log.Fatalf("Error updating device info: %v", err)
	}

	log.Println("Device information successfully collected and stored.")
}

func getDeviceInfo() (DeviceInfo, error) {
	mac, err := getMacAddress()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("network info error: %w", err)
	}

	tpmData, err := getTpmDetails()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("TPM details error: %w", err)
	}

	sse42Supported := checkSSE42()
	totalMemory := getTotalMemory()

	return DeviceInfo{
		MACAddress:     mac,
		SSE42:          sse42Supported,
		TPMEnabled:     tpmData.Enabled,
		HighestVersion: tpmData.HighestVersion,
		TotalMemory:    totalMemory,
	}, nil
}

func getTpmDetails() (TpmDetails, error) {
	psScript := `
	$returned = Get-WmiObject -Namespace "Root\CIMv2\Security\MicrosoftTpm" -Class Win32_Tpm
	$tpmEnabled = $returned.IsEnabled_InitialValue -eq $true
	$specVersion = $returned.SpecVersion
	if ($specVersion -is [string]) {
	    $splitVersions = $specVersion -split ", "
	} else {
	    $splitVersions = @($specVersion)
	}
	$highestVersion = $splitVersions | Sort-Object -Descending | Select-Object -First 1
	@{"Enabled" = $tpmEnabled; "HighestVersion" = $highestVersion;} | ConvertTo-Json
	`

	output, err := runPowerShell(psScript)
	if err != nil {
		return TpmDetails{}, err
	}

	tpmData := make(map[string]interface{})
	err = json.Unmarshal([]byte(output), &tpmData)
	if err != nil {
		return TpmDetails{}, fmt.Errorf("failed to parse JSON: %w", err)
	}

	enabled, ok := tpmData["Enabled"].(bool)
	if !ok {
		return TpmDetails{}, fmt.Errorf("unexpected type for Enabled field")
	}

	highestVersionStr, ok := tpmData["HighestVersion"].(string)
	if !ok || highestVersionStr == "" {
		highestVersionStr = "0"
	}		

	highestVersion, err := strconv.ParseFloat(highestVersionStr, 64)
	if err != nil {
		return TpmDetails{}, fmt.Errorf("failed to parse highest version: %w", err)
	}

	return TpmDetails{Enabled: enabled, HighestVersion: highestVersion}, nil
}

func runPowerShell(script string) (string, error) {
	cmd := exec.Command("powershell", "-Command", script)
	var out bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("PowerShell error: %s", stderr.String())
	}
	return strings.TrimSpace(out.String()), nil
}

func getMacAddress() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("failed to get network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				if ipNet, ok := addr.(*net.IPNet); ok && !ipNet.IP.IsLoopback() {
					if ipNet.IP.To4() != nil && strings.HasPrefix(ipNet.IP.String(), "10.1") {
						return iface.HardwareAddr.String(), nil
					}
				}
			}
		}
	}

	return "", fmt.Errorf("no suitable network interface found")
}

func checkSSE42() bool {
	r1, _, _ := procIsProcessorFeaturePresent.Call(uintptr(FEATURE_SSE42))
	return r1 != 0
}

func getTotalMemory() int {
	var memStat MEMORYSTATUSEX
	memStat.Length = uint32(unsafe.Sizeof(memStat))

	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memStat)))
	if r1 == 0 {
		log.Println("Failed to retrieve memory information")
		return 0
	}

	return int(memStat.TotalPhys / 1024 / 1024)
}

func upsertDeviceInfo(device DeviceInfo) error {
	query := `
        MERGE TPMStatus AS target
        USING (SELECT @MACAddress AS MACAddress) AS source
        ON (target.MACAddress = source.MACAddress)
        WHEN MATCHED THEN 
            UPDATE SET
                SSE42 = @SSE42, 
                TPMEnabled = @TPMEnabled, 
                HighestVersion = @HighestVersion, 
                TotalMemory = @TotalMemory
        WHEN NOT MATCHED THEN 
            INSERT (MACAddress, SSE42, TPMEnabled, HighestVersion, TotalMemory) 
            VALUES (@MACAddress, @SSE42, @TPMEnabled, @HighestVersion, @TotalMemory);`

	_, err := db.Exec(query,
		sql.Named("MACAddress", device.MACAddress),
		sql.Named("SSE42", device.SSE42),
		sql.Named("TPMEnabled", device.TPMEnabled),
		sql.Named("HighestVersion", device.HighestVersion),
		sql.Named("TotalMemory", device.TotalMemory))
	if err != nil {
		return fmt.Errorf("error upserting device info: %w", err)
	}

	return nil
}