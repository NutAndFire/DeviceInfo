/*
Author: Christopher Bleakley
Email: chris@io-comms.co.uk
Date: 22-01-2025
Description: This tool collects device information (username, IP address, MAC address) and stores it in a database.
Version: 1.1.8
*/

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net"
	"os"
	"time"
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
	Username   	string
	Hostname   	string
	IPAddress  	string
	MACAddress 	string
	Build      	int
	Minor		int
}

type RTL_OSVERSIONINFOW struct {
	dwOSVersionInfoSize uint32
	dwMajorVersion uint32
	dwMinorVersion uint32
	dwBuildNumber uint32
	dwPlatformId uint32
	szCSDVersion [128]uint16
}

type VS_FIXEDFILEINFO struct {
    dwSignature        uint32
    dwStrucVersion     uint32
    dwFileVersionMS    uint32
    dwFileVersionLS    uint32
    dwProductVersionMS uint32
    dwProductVersionLS uint32
    dwFileFlagsMask    uint32
    dwFileFlags        uint32
    dwFileOS           uint32
    dwFileType         uint32
    dwFileSubtype      uint32
    dwFileDateMS       uint32
    dwFileDateLS       uint32
}

var (
	db      *sql.DB
	Version = "1.1.8"
)

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
		log.Fatalf("Failed to connect to the database: %v", err)
	}
	defer db.Close()

	// Configure connection pool
	db.SetConnMaxLifetime(30 * time.Minute)
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)

	for {
		// Recover from panics to prevent the application from exiting
		func() {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("Application crashed with error: %v. Restarting...", r)
				}
			}()

			run()
		}()
		time.Sleep(5 * time.Minute) // Prevent tight restart loops
	}
}

func run() {
	deviceInfo, err := getDeviceInfo()
	if err != nil {
		log.Printf("Failed to get device info: %v", err)
		return
	}

	// Initial database insertion with LoginTime
	err = upsertDeviceInfo(deviceInfo, true)
	if err != nil {
		log.Printf("Failed to upsert device info: %v", err)
		return
	}

	// Scheduler: Update LastUpdate every hour
	ticker := time.NewTicker(20 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := upsertDeviceInfo(deviceInfo, false)
			if err != nil {
				log.Printf("Error updating LastUpdate: %v", err)
			}
		}
	}
}

// Don't update if Administrator logs in
func validateUsername(username string) bool {
	if username == "Administrator" {
		return false
	} else {
		return true
	}
}

// getDeviceInfo collects username, IP address, and MAC address
func getDeviceInfo() (DeviceInfo, error) {
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}	

	// Validate Administrator has not logged in
	if !validateUsername(username) {
		return DeviceInfo{}, fmt.Errorf("invalid username format: %s", username)
	}

	versionDLL := syscall.NewLazyDLL("version.dll")
    getFileVersionInfoSize := versionDLL.NewProc("GetFileVersionInfoSizeW")
    getFileVersionInfo := versionDLL.NewProc("GetFileVersionInfoW")
    verQueryValue := versionDLL.NewProc("VerQueryValueW")

	filename, _ := syscall.UTF16PtrFromString("C:\\Windows\\System32\\ntoskrnl.exe")
    var handle uint32
	r1, _, err := getFileVersionInfoSize.Call(uintptr(unsafe.Pointer(filename)), uintptr(unsafe.Pointer(&handle)))
	size := uint32(r1)
	if size == 0 {		
        return  DeviceInfo{}, fmt.Errorf("Error getting version info size: %s", err)
    }

	buffer := make([]byte, size)
    ret, _, err := getFileVersionInfo.Call(uintptr(unsafe.Pointer(filename)), uintptr(unsafe.Pointer(&handle)), uintptr(size), uintptr(unsafe.Pointer(&buffer[0])))
    if ret == 0 {
        return DeviceInfo{}, fmt.Errorf("Error getting version info: %s", err)
    }

	var verInfo *VS_FIXEDFILEINFO
    var verSize uint32
    ret, _, err = verQueryValue.Call(uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("\\"))), uintptr(unsafe.Pointer(&verInfo)), uintptr(unsafe.Pointer(&verSize)))
    if ret == 0 {
        return DeviceInfo{}, fmt.Errorf("Error querying version value: %s", err)
    }

	build := int(verInfo.dwFileVersionLS>>16)
	minor := int(verInfo.dwFileVersionLS&0xFFFF)

	hostname, err := os.Hostname()
	if err != nil {
		return DeviceInfo{}, fmt.Errorf("error fetching hostname: %v", err)
	}

	ip, mac, err := getNetworkInfo()
	if err != nil {
		return DeviceInfo{}, err
	}

	return DeviceInfo{
		Username:   username,
		Hostname:   hostname,
		IPAddress:  ip,
		MACAddress: mac,
		Build:      build,
		Minor:      minor,	
	}, nil
}

// getNetworkInfo retrieves the IP and MAC address of a suitable interface
func getNetworkInfo() (string, string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", "", err
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				switch v := addr.(type) {
				case *net.IPNet:
					if !v.IP.IsLoopback() && v.IP.To4() != nil {
						ip := v.IP.String()
						if isInSubnet(v.IP) {
							return ip, iface.HardwareAddr.String(), nil
						}
					}
				}
			}
		}
	}

	return "", "", fmt.Errorf("no suitable network interface found with IP starting with 10.1")
}

// isInSubnet checks if the given IP address starts with 10.1
func isInSubnet(ip net.IP) bool {
	return strings.HasPrefix(ip.String(), "10.1")
}

func upsertDeviceInfo(device DeviceInfo, updateLoginTime bool) error {
	if updateLoginTime {
		upsertQuery := `
            MERGE DeviceInfo AS target
            USING (SELECT @MACAddress AS MACAddress) AS source
            ON (target.MACAddress = source.MACAddress)
            WHEN MATCHED THEN 
                UPDATE SET 
                    Username = @Username, 
                    IPAddress = @IPAddress, 
                    Hostname = @Hostname, 
                    LoginTime = GETDATE(),
                    Version = @Version,
                    Build = @Build,
					Minor = @Minor
            WHEN NOT MATCHED THEN 
                INSERT (Username, IPAddress, MACAddress, Hostname, LoginTime, LastUpdate, Version, Build, Minor) 
                VALUES (@Username, @IPAddress, @MACAddress, @Hostname, GETDATE(), NULL, @Version, @Build, @Minor);`
		_, err := db.Exec(upsertQuery,
			sql.Named("Username", device.Username),
			sql.Named("IPAddress", device.IPAddress),
			sql.Named("MACAddress", device.MACAddress),
			sql.Named("Hostname", device.Hostname),
			sql.Named("Version", Version),
			sql.Named("Build", device.Build),
			sql.Named("Minor", device.Minor))
		if err != nil {
			return fmt.Errorf("error upserting record with LoginTime: %v", err)
		}
	} else {
		updateQuery := `
            UPDATE DeviceInfo
            SET 
                LastUpdate = GETDATE(),
                Username = @Username, 
                IPAddress = @IPAddress, 
                Hostname = @Hostname, 
                Build = @Build,
				Minor = @Minor
            WHERE MACAddress = @MACAddress`
		_, err := db.Exec(updateQuery,
			sql.Named("Username", device.Username),
			sql.Named("IPAddress", device.IPAddress),
			sql.Named("MACAddress", device.MACAddress),
			sql.Named("Hostname", device.Hostname),
			sql.Named("Build", device.Build),
			sql.Named("Minor", device.Minor))
		if err != nil {
			return fmt.Errorf("error updating LastUpdate: %v", err)
		}
	}

	return nil
}