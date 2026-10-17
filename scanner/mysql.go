package scanner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/4lch3mis7/webzoro-golang/utils"
	"github.com/go-sql-driver/mysql"
)

// Internal capability and status bitmasks for MySQL handshake parsing
const (
	clientLocalFiles uint32 = 1 << 7
	clientSSL        uint32 = 1 << 11
	clientSecureConn uint32 = 1 << 15
	clientPluginAuth uint32 = 1 << 19
	statusAutocommit uint16 = 1 << 1
)

var capabilityTable = []struct {
	mask uint32
	name string
}{
	{1 << 0, "LongPassword"},
	{1 << 1, "FoundRows"},
	{1 << 2, "LongColumnFlag"},
	{1 << 3, "ConnectWithDatabase"},
	{1 << 5, "SupportsCompression"},
	{1 << 6, "ODBCClient"},
	{1 << 7, "SupportsLoadDataLocal"},
	{1 << 8, "IgnoreSpaceBeforeParenthesis"},
	{1 << 9, "Speaks41ProtocolNew"},
	{1 << 10, "InteractiveClient"},
	{1 << 11, "SwitchToSSLAfterHandshake"},
	{1 << 12, "IgnoreSigpipes"},
	{1 << 13, "SupportsTransactions"},
	{1 << 15, "Support41Auth"},
	{1 << 16, "SupportsMultipleStatements"},
	{1 << 17, "SupportsMultipleResults"},
	{1 << 19, "SupportsAuthPlugins"},
}

var defaultMySQLUsernames = utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Usernames/top-usernames-shortlist.txt")
var defaultMySQLPasswords = utils.ReadLinesRemote("https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt")
var defaultMySQLCreds []struct {
	user string
	pass string
}

func init() {
	for _, u := range defaultMySQLUsernames {
		for _, p := range defaultMySQLPasswords {
			defaultMySQLCreds = append(defaultMySQLCreds, struct {
				user string
				pass string
			}{u, p})
		}
	}
}

// MySQLAuditResult stores the security evaluation of a MySQL service (via native handshake).
type MySQLAuditResult struct {
	Target               string   `json:"target,omitempty"`
	Port                 int      `json:"port"`
	ProtocolVersion      int      `json:"protocol_version"`
	ServerVersion        string   `json:"server_version"`
	ConnectionID         uint32   `json:"connection_id"`
	AuthPlugin           string   `json:"auth_plugin"`
	SaltHex              string   `json:"salt_hex,omitempty"`
	StatusFlags          uint16   `json:"status_flags"`
	StatusDesc           string   `json:"status_desc,omitempty"`
	CharsetID            uint8    `json:"charset_id"`
	SSLSupported         bool     `json:"ssl_supported"`
	LocalFilesAllowed    bool     `json:"local_files_allowed"`
	EmptyPasswordAllowed bool     `json:"empty_password_allowed"`
	AccessibleUser       string   `json:"accessible_user,omitempty"`
	DefaultAccess        string   `json:"default_access,omitempty"`
	Capabilities         []string `json:"capabilities,omitempty"`
	Recommendations      []string `json:"recommendations,omitempty"`
}

func (r MySQLAuditResult) String() string {
	var sb strings.Builder
	targetStr := fmt.Sprintf(" (%s:%d)", r.Target, r.Port)
	if r.Target == "" {
		targetStr = fmt.Sprintf(" (Port %d)", r.Port)
	}
	sb.WriteString(fmt.Sprintf("\n[+] MySQL Native Service Audit%s:\n", targetStr))

	if r.ServerVersion != "" {
		sb.WriteString(fmt.Sprintf("    Server Version  : %s (Protocol v%d)\n", r.ServerVersion, r.ProtocolVersion))
	}
	if r.ConnectionID > 0 {
		sb.WriteString(fmt.Sprintf("    Connection ID   : %d\n", r.ConnectionID))
	}
	if r.AuthPlugin != "" {
		sb.WriteString(fmt.Sprintf("    Auth Plugin     : %s\n", r.AuthPlugin))
	}
	if r.StatusDesc != "" {
		sb.WriteString(fmt.Sprintf("    Status Flags    : %s\n", r.StatusDesc))
	}

	sslStatus := "Disabled / Not Supported"
	if r.SSLSupported {
		sslStatus = "Supported (SwitchToSSLAfterHandshake)"
	}
	sb.WriteString(fmt.Sprintf("    SSL/TLS Support : %s\n", sslStatus))

	if len(r.Capabilities) > 0 {
		sb.WriteString(fmt.Sprintf("    Capabilities    : %s\n", strings.Join(r.Capabilities, ", ")))
	}

	if r.SaltHex != "" {
		sb.WriteString(fmt.Sprintf("    Salt (Challenge): %s\n", r.SaltHex))
	}

	if r.DefaultAccess != "" {
		sb.WriteString(fmt.Sprintf("    Default Access  : %s\n", r.DefaultAccess))
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString("    Remediation / Hardening:\n")
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("      - %s\n", rec))
		}
	}

	return sb.String()
}

// AuditMySQL performs a native security and handshake audit on MySQL,
// evaluating capabilities and testing default credentials using the official MySQL connector.
func AuditMySQL(t *Target, p Port) MySQLAuditResult {
	result := MySQLAuditResult{
		Target: t.Target,
		Port:   p.Port,
	}

	addr := net.JoinHostPort(t.Target, fmt.Sprintf("%d", p.Port))
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		result.DefaultAccess = fmt.Sprintf("Direct connect blocked/timed out: %v", err)
		return result
	}

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	handshake, err := readMySQLPacket(conn)
	conn.Close()
	if err != nil {
		result.DefaultAccess = fmt.Sprintf("Handshake read failed: %v", err)
		return result
	}

	// Parse handshake metadata
	parseHandshake(handshake, &result)

	// Probe default / weak credentials using the Go MySQL connector
	var lastErr error
	for _, cred := range defaultMySQLCreds {
		ok, err := probeCredentials(t.Target, p.Port, cred.user, cred.pass)
		if ok {
			result.EmptyPasswordAllowed = (cred.pass == "")
			result.AccessibleUser = cred.user
			passLabel := "blank/empty"
			if cred.pass != "" {
				passLabel = fmt.Sprintf("'%s'", cred.pass)
			}
			result.DefaultAccess = fmt.Sprintf("[!] CRITICAL: Default credentials accepted ('%s':%s)!", cred.user, passLabel)
			break
		}
		if err != nil {
			lastErr = err
		}
	}

	if result.DefaultAccess == "" {
		if lastErr != nil && strings.Contains(lastErr.Error(), "1130") {
			result.DefaultAccess = "Host not allowed to connect (Code 1130)"
		} else {
			result.DefaultAccess = "Denied (Password required for default accounts)"
		}
	}

	// Construct security and hardening recommendations based purely on native probe results
	if result.AccessibleUser != "" {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("CRITICAL: Set a strong password for '%s' immediately (e.g. ALTER USER '%s'@'%%' IDENTIFIED BY '...';)", result.AccessibleUser, result.AccessibleUser))
	}
	if !result.SSLSupported {
		result.Recommendations = append(result.Recommendations,
			"Enable SSL/TLS (require_secure_transport = ON) to prevent plaintext credential sniffing on port 3306.")
	}
	if result.LocalFilesAllowed {
		result.Recommendations = append(result.Recommendations,
			"Server allows CLIENT_LOCAL_FILES. Disable 'local_infile = OFF' to prevent arbitrary file read attacks via rogue servers.")
	}
	if result.AuthPlugin == "mysql_native_password" {
		result.Recommendations = append(result.Recommendations,
			"Consider migrating from legacy 'mysql_native_password' to 'caching_sha2_password' for enhanced hash security.")
	}
	result.Recommendations = append(result.Recommendations,
		"Ensure bind-address = 127.0.0.1 in my.cnf if external database access is not required.")

	return result
}

// readMySQLPacket reads a single standard MySQL protocol packet.
func readMySQLPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}

	return payload, nil
}

// parseHandshake extracts complete server version, capabilities, status, and auth plugin from HandshakeV10.
func parseHandshake(data []byte, res *MySQLAuditResult) {
	if len(data) < 15 {
		return
	}

	res.ProtocolVersion = int(data[0])
	rest := data[1:]

	// Server version (null-terminated string)
	idx := bytes.IndexByte(rest, 0)
	if idx == -1 {
		return
	}
	res.ServerVersion = string(rest[:idx])
	rest = rest[idx+1:]

	// Connection / Thread ID (4 bytes uint32)
	if len(rest) < 4 {
		return
	}
	res.ConnectionID = binary.LittleEndian.Uint32(rest[:4])
	rest = rest[4:]

	// Auth-plugin-data part 1 (8 bytes)
	var salt []byte
	if len(rest) >= 8 {
		salt = append(salt, rest[:8]...)
		rest = rest[8:]
	}

	// Filler (1 byte, 0x00)
	if len(rest) >= 1 {
		rest = rest[1:]
	}

	// Capability flags lower (2 bytes)
	if len(rest) < 2 {
		return
	}
	capLower := binary.LittleEndian.Uint16(rest[:2])
	rest = rest[2:]

	var capUpper uint16
	var authPluginDataLen int

	if len(rest) >= 1 {
		res.CharsetID = rest[0]
		rest = rest[1:]
	}

	if len(rest) >= 2 {
		res.StatusFlags = binary.LittleEndian.Uint16(rest[:2])
		if res.StatusFlags&statusAutocommit != 0 {
			res.StatusDesc = "Autocommit"
		}
		rest = rest[2:]
	}

	if len(rest) >= 2 {
		capUpper = binary.LittleEndian.Uint16(rest[:2])
		rest = rest[2:]
	}

	capabilities := uint32(capLower) | uint32(capUpper)<<16

	// Decode capability flags into human-readable list
	res.Capabilities = decodeCapabilities(capabilities)
	res.SSLSupported = (capabilities&clientSSL != 0)
	res.LocalFilesAllowed = (capabilities&clientLocalFiles != 0)

	// Auth plugin data len (1 byte)
	if len(rest) >= 1 {
		authPluginDataLen = int(rest[0])
		rest = rest[1:]
	}

	// Reserved (10 bytes)
	if len(rest) >= 10 {
		rest = rest[10:]
	}

	// Auth-plugin-data part 2
	if capabilities&clientSecureConn != 0 {
		len2 := 12
		if authPluginDataLen > 8 {
			len2 = authPluginDataLen - 8
			if len2 > len(rest) {
				len2 = len(rest)
			}
		}
		if len(rest) >= len2 {
			part2 := bytes.TrimRight(rest[:len2], "\x00")
			salt = append(salt, part2...)
			rest = rest[len2:]
		}
	}

	if len(salt) > 0 {
		res.SaltHex = hex.EncodeToString(salt)
	}

	// Auth plugin name (null-terminated string)
	if capabilities&clientPluginAuth != 0 {
		rest = bytes.TrimLeft(rest, "\x00")
		idx = bytes.IndexByte(rest, 0)
		if idx != -1 {
			res.AuthPlugin = string(rest[:idx])
		} else if len(rest) > 0 {
			res.AuthPlugin = string(rest)
		}
	}

	// Fallback plugin name detection if needed
	if res.AuthPlugin == "" && len(data) > 30 {
		for _, name := range []string{"mysql_native_password", "caching_sha2_password", "sha256_password", "mysql_old_password"} {
			if bytes.Contains(data, []byte(name)) {
				res.AuthPlugin = name
				break
			}
		}
	}
}

// decodeCapabilities maps capability bitmask to readable capability names.
func decodeCapabilities(caps uint32) []string {
	var names []string
	for _, entry := range capabilityTable {
		if caps&entry.mask != 0 {
			names = append(names, entry.name)
		}
	}
	return names
}

// probeCredentials tests if the given user/password can successfully authenticate against the MySQL server
// using the official Go MySQL database connector, supporting all auth methods including caching_sha2_password.
// It tries two connection modes: plain TCP first (covers mysql_native_password and cached caching_sha2_password),
// then TLS skip-verify (covers caching_sha2_password full-auth path over TLS).
func probeCredentials(host string, port int, username, password string) (bool, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	// Mode 1: plain TCP (works for mysql_native_password and caching_sha2_password cache-hit)
	cfg := mysql.NewConfig()
	cfg.User = username
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.Timeout = 3 * time.Second
	cfg.ReadTimeout = 3 * time.Second
	cfg.WriteTimeout = 3 * time.Second
	cfg.AllowNativePasswords = true

	if db, err := sql.Open("mysql", cfg.FormatDSN()); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		pingErr := db.PingContext(ctx)
		cancel()
		db.Close()
		if pingErr == nil {
			return true, nil
		}
	}

	// Mode 2: TLS skip-verify (required for caching_sha2_password cache-miss / full-auth path)
	cfgTLS := mysql.NewConfig()
	cfgTLS.User = username
	cfgTLS.Passwd = password
	cfgTLS.Net = "tcp"
	cfgTLS.Addr = addr
	cfgTLS.Timeout = 3 * time.Second
	cfgTLS.ReadTimeout = 3 * time.Second
	cfgTLS.WriteTimeout = 3 * time.Second
	cfgTLS.AllowNativePasswords = true
	cfgTLS.AllowCleartextPasswords = true
	cfgTLS.TLSConfig = "skip-verify"

	dbTLS, err := sql.Open("mysql", cfgTLS.FormatDSN())
	if err != nil {
		return false, err
	}
	defer dbTLS.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = dbTLS.PingContext(ctx)
	if err == nil {
		return true, nil
	}
	return false, err
}
