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
	passwords := append([]string{""}, defaultMySQLPasswords...)
	for _, u := range defaultMySQLUsernames {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		for _, p := range passwords {
			p = strings.TrimRight(p, "\r")
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
	sb.WriteString(fmt.Sprintf("\n%s %s%s:\n", utils.TagSuccess(), utils.ColorHeader.Sprint("MySQL Native Service Audit"), utils.ColorHighlight.Sprint(targetStr)))

	if r.ServerVersion != "" {
		sb.WriteString(fmt.Sprintf("    %-16s: %s (Protocol v%d)\n", utils.ColorBold.Sprint("Server Version"), utils.ColorHighlight.Sprint(r.ServerVersion), r.ProtocolVersion))
	}
	if r.ConnectionID > 0 {
		sb.WriteString(fmt.Sprintf("    %-16s: %d\n", utils.ColorBold.Sprint("Connection ID"), r.ConnectionID))
	}
	if r.AuthPlugin != "" {
		sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("Auth Plugin"), utils.ColorVersion.Sprint(r.AuthPlugin)))
	}
	if r.StatusDesc != "" {
		sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("Status Flags"), r.StatusDesc))
	}

	sslStatus := utils.ColorWarn.Sprint("Disabled / Not Supported")
	if r.SSLSupported {
		sslStatus = utils.ColorSuccess.Sprint("Supported (SwitchToSSLAfterHandshake)")
	}
	sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("SSL/TLS Support"), sslStatus))

	if len(r.Capabilities) > 0 {
		sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("Capabilities"), strings.Join(r.Capabilities, ", ")))
	}

	if r.SaltHex != "" {
		sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("Salt (Challenge)"), utils.ColorDim.Sprint(r.SaltHex)))
	}

	if r.DefaultAccess != "" {
		sb.WriteString(fmt.Sprintf("    %-16s: %s\n", utils.ColorBold.Sprint("Default Access"), utils.ColorRiskText(r.DefaultAccess)))
	}

	if len(r.Recommendations) > 0 {
		sb.WriteString(fmt.Sprintf("    %s\n", utils.ColorBold.Sprint("Remediation / Hardening:")))
		for _, rec := range r.Recommendations {
			sb.WriteString(fmt.Sprintf("      - %s\n", utils.ColorRiskText(rec)))
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
			t.Credentials = append(t.Credentials, struct {
				Service  string
				Port     int
				Username string
				Password string
			}{"mysql", p.Port, cred.user, cred.pass})
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

// EnumerateMySQL performs a comprehensive enumeration of MySQL schema, users, and privileges.
func EnumerateMySQL(t *Target) {
	var username, password string
	port := 3306

	for _, cred := range t.Credentials {
		if cred.Service == "mysql" {
			port = cred.Port
			username = cred.Username
			password = cred.Password
			break
		}
	}

	if username == "" {
		utils.LogError("No credentials found for MySQL server")
		return
	}

	addr := net.JoinHostPort(t.Target, fmt.Sprintf("%d", port))
	cfg := mysql.NewConfig()
	cfg.User = username
	cfg.Passwd = password
	cfg.Net = "tcp"
	cfg.Addr = addr
	cfg.Timeout = 5 * time.Second
	cfg.ReadTimeout = 5 * time.Second
	cfg.WriteTimeout = 5 * time.Second
	cfg.AllowNativePasswords = true

	db, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil || db.Ping() != nil {
		if db != nil {
			db.Close()
		}
		cfg.AllowCleartextPasswords = true
		cfg.TLSConfig = "skip-verify"
		db, err = sql.Open("mysql", cfg.FormatDSN())
		if err != nil {
			utils.LogError("Failed to open MySQL connection: %v", err)
			return
		}
	}
	defer db.Close()

	db.SetConnMaxLifetime(5 * time.Second)
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(0)

	if err = db.Ping(); err != nil {
		utils.LogError("Failed to connect to MySQL server: %v", err)
		return
	}
	fmt.Printf("\n%s %s (%s@%s):\n", utils.TagSuccess(), utils.ColorHeader.Sprint("MySQL Enumeration"), utils.ColorHighlight.Sprint(username), utils.ColorPortNum.Sprint(addr))

	// --- Databases ---
	dbRows, err := db.Query("SHOW DATABASES")
	if err != nil {
		fmt.Printf("    %s Failed to list databases: %v\n", utils.TagError(), err)
		return
	}
	var databases []string
	for dbRows.Next() {
		var name string
		if err := dbRows.Scan(&name); err == nil {
			databases = append(databases, name)
		}
	}
	dbRows.Close()

	fmt.Printf("    %s (%d): %s\n", utils.ColorBold.Sprint("Databases"), len(databases), strings.Join(databases, ", "))

	// --- Tables per database (verbose only) ---
	if t.Verbose {
		for _, dbName := range databases {
			tableRows, err := db.Query(
				"SELECT TABLE_NAME, TABLE_TYPE, TABLE_ROWS "+
					"FROM information_schema.TABLES WHERE TABLE_SCHEMA = ? "+
					"ORDER BY TABLE_TYPE, TABLE_NAME", dbName)
			if err != nil {
				fmt.Printf("      [%s] tables: %v\n", utils.ColorInfo.Sprint(dbName), err)
				continue
			}
			var tables []string
			for tableRows.Next() {
				var tName, tType string
				var tRows sql.NullInt64
				if err := tableRows.Scan(&tName, &tType, &tRows); err == nil {
					rowCount := "?"
					if tRows.Valid {
						rowCount = fmt.Sprintf("%d rows", tRows.Int64)
					}
					tables = append(tables, fmt.Sprintf("%s (%s, %s)", tName, tType, rowCount))
				}
			}
			tableRows.Close()

			if len(tables) == 0 {
				fmt.Printf("      [%s] (empty)\n", utils.ColorInfo.Sprint(dbName))
			} else {
				fmt.Printf("      [%s] %d table(s):\n", utils.ColorInfo.Sprint(dbName), len(tables))
				for _, tbl := range tables {
					fmt.Printf("        - %s\n", tbl)
				}
			}
		}
	}

	// --- Users ---
	userRows, err := db.Query("SELECT user, host, plugin FROM mysql.user ORDER BY user, host")
	if err != nil {
		fmt.Printf("    %s Users: permission denied or unavailable\n", utils.TagError())
	} else {
		defer userRows.Close()
		fmt.Printf("    %s\n", utils.ColorBold.Sprint("Users:"))
		for userRows.Next() {
			var user, host, plugin string
			if err := userRows.Scan(&user, &host, &plugin); err == nil {
				fmt.Printf("      - '%s'@'%s' [plugin: %s]\n", utils.ColorHighlight.Sprint(user), host, utils.ColorVersion.Sprint(plugin))
			}
		}
	}
	var currentUser string
	_ = db.QueryRow("SELECT CURRENT_USER()").Scan(&currentUser)
	if currentUser != "" {
		fmt.Printf("    %s: %s\n", utils.ColorBold.Sprint("Current User"), utils.ColorHighlight.Sprint(currentUser))
	}

	// --- Security-critical server variables ---
	secVars := []string{
		"bind_address",
		"require_secure_transport",
		"local_infile",
		"persist_sensitive_variables_in_plaintext",
		"default_authentication_plugin",
	}
	varQuery := fmt.Sprintf("SHOW VARIABLES WHERE Variable_name IN ('%s')", strings.Join(secVars, "', '"))
	varRows, err := db.Query(varQuery)
	if err != nil {
		fmt.Printf("    %s Security variables: %v\n", utils.TagError(), err)
	} else {
		defer varRows.Close()
		fmt.Printf("    %s\n", utils.ColorBold.Sprint("Security Variables:"))
		for varRows.Next() {
			var varName, varValue string
			if err := varRows.Scan(&varName, &varValue); err == nil {
				risk := secVarRisk(varName, varValue)
				fmt.Printf("      %-42s = %-24s %s\n", utils.ColorService.Sprint(varName), varValue, utils.ColorRiskText(risk))
			}
		}
	}

	// --- Grants (verbose only) ---
	if t.Verbose {
		grantRows, err := db.Query("SHOW GRANTS")
		if err == nil {
			defer grantRows.Close()
			fmt.Printf("    %s\n", utils.ColorBold.Sprint("Grants:"))
			for grantRows.Next() {
				var grant string
				if err := grantRows.Scan(&grant); err == nil {
					fmt.Printf("      %s\n", grant)
				}
			}
		}
	}
}

// secVarRisk evaluates the security impact of a MySQL server variable value.
func secVarRisk(name, val string) string {
	valLower := strings.ToLower(val)
	switch strings.ToLower(name) {
	case "bind_address":
		if val == "0.0.0.0" || val == "::" || val == "*" {
			return "[!] CRITICAL: Listens on all interfaces (publicly accessible)"
		} else if val == "127.0.0.1" || val == "::1" || valLower == "localhost" {
			return "[SECURE] Bound to loopback interface only"
		}
		return fmt.Sprintf("[i] Bound to %s", val)
	case "require_secure_transport":
		if valLower == "on" || valLower == "1" {
			return "[SECURE] Enforced (Plaintext connections rejected)"
		}
		return "[!] WARNING: Disabled (Plaintext credentials allowed)"
	case "local_infile":
		if valLower == "on" || valLower == "1" {
			return "[!] WARNING: Enabled (Arbitrary client file read risk)"
		}
		return "[SECURE] Disabled"
	case "persist_sensitive_variables_in_plaintext":
		if valLower == "on" || valLower == "1" {
			return "[!] WARNING: Sensitive variables persisted in plaintext on disk"
		}
		return "[SECURE] Disabled"
	case "default_authentication_plugin":
		if strings.Contains(valLower, "native_password") {
			return "[!] WARNING: Legacy SHA-1 auth (vulnerable to offline cracking)"
		} else if strings.Contains(valLower, "caching_sha2") {
			return "[SECURE] SHA-256 caching auth"
		}
	}
	return ""
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
