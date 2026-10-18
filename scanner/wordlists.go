package scanner

// ============================================================================
// Directory Enumeration Wordlists
// ============================================================================

// DefaultPHPWordlist provides a curated fallback list of sensitive PHP endpoints.
var DefaultPHPWordlist = []string{
	"index.php",
	"config.php",
	"config.inc.php",
	"configuration.php",
	"wp-config.php",
	"wp-login.php",
	"admin.php",
	"admin/index.php",
	"login.php",
	"user.php",
	"users.php",
	"auth.php",
	"dashboard.php",
	"db.php",
	"database.php",
	"connect.php",
	"connection.php",
	"conn.php",
	"sql.php",
	"info.php",
	"phpinfo.php",
	"test.php",
	"upload.php",
	"uploader.php",
	"file.php",
	"download.php",
	"setup.php",
	"install.php",
	"update.php",
	"upgrade.php",
	"shell.php",
	"cmd.php",
	"eval.php",
	"xmlrpc.php",
	"api.php",
	"ajax.php",
	"search.php",
	"profile.php",
	"register.php",
	"logout.php",
	"cron.php",
	"backup.php",
	"dump.php",
	"export.php",
	"import.php",
	"functions.php",
	"header.php",
	"footer.php",
	"common.php",
	"main.php",
	"home.php",
	"status.php",
	"health.php",
}

// defaultPHPWordlist alias for backward compatibility within package scanner.
var defaultPHPWordlist = DefaultPHPWordlist

// DefaultHighImpactWordlist contains curated, high-priority routes and sensitive files for web enumeration.
var DefaultHighImpactWordlist = []string{
	// Admin & Authentication
	"admin",
	"admin/",
	"admin/login",
	"admin/login.php",
	"admin/index.php",
	"administrator",
	"administrator/",
	"login",
	"login.php",
	"signin",
	"auth",
	"authenticate",
	"portal",
	"controlpanel",
	"cpanel",
	"dashboard",
	"manage",
	"management",
	"wp-admin",
	"wp-login.php",
	"user/login",
	"account/login",

	// Version Control & Repositories
	".git",
	".git/HEAD",
	".git/config",
	".git/index",
	".gitignore",
	".gitlab-ci.yml",
	".github",
	".svn",
	".svn/entries",
	".hg",
	".bzr",

	// Environment & Configuration Secrets
	".env",
	".env.local",
	".env.production",
	".env.development",
	".env.example",
	".env.bak",
	".env.save",
	"config.php",
	"config.php.bak",
	"config.json",
	"config.yml",
	"config.yaml",
	"configuration.php",
	"settings.py",
	"database.yml",
	"secrets.yml",
	"wp-config.php",
	"wp-config.php.bak",
	"wp-config.old",
	"web.config",
	"appsettings.json",
	"appsettings.Development.json",

	// APIs, Documentation & Schemas
	"api",
	"api/",
	"api/v1",
	"api/v2",
	"api/v3",
	"swagger",
	"swagger/",
	"swagger/index.html",
	"swagger-ui",
	"swagger-ui.html",
	"swagger.json",
	"swagger.yaml",
	"openapi.json",
	"openapi.yaml",
	"docs",
	"docs/",
	"api-docs",
	"api-docs/",
	"graphql",
	"graphiql",
	"v1",
	"v2",

	// Backups, Dumps & Archives
	"backup",
	"backup/",
	"backups",
	"backups/",
	"backup.zip",
	"backup.tar.gz",
	"backup.tar",
	"backup.sql",
	"backup.bak",
	"dump.sql",
	"db.sql",
	"data.sql",
	"database.sql",
	"site.zip",
	"site.tar.gz",
	"archive.zip",
	"www.zip",

	// Diagnostics, Health & Status
	"phpinfo.php",
	"info.php",
	"test.php",
	"health",
	"healthz",
	"live",
	"ready",
	"actuator",
	"actuator/health",
	"actuator/env",
	"actuator/info",
	"server-status",
	"status",
	"metrics",
	"debug",
	"trace",
	"console",

	// Common Sensitive Files & Policies
	"robots.txt",
	"sitemap.xml",
	".well-known/security.txt",
	"crossdomain.xml",
	"clientaccesspolicy.xml",
	"composer.json",
	"composer.lock",
	"package.json",
	"package-lock.json",
	"Dockerfile",
	"docker-compose.yml",
	"Makefile",

	// Common Directories
	"uploads",
	"uploads/",
	"upload",
	"files",
	"files/",
	"static",
	"static/",
	"assets",
	"assets/",
	"images",
	"images/",
	"media",
	"includes",
	"inc",
	"temp",
	"tmp",
	"test",
	"dev",
	"staging",
	"internal",
	"private",
	"secret",
	"keys",
	"certs",
	"logs",
	"log",
}

// defaultHighImpactWordlist alias for backward compatibility within package scanner.
var defaultHighImpactWordlist = DefaultHighImpactWordlist

// ============================================================================
// Entity & Verb Knowledge Bases (Semantic Parameter & IDOR Mining)
// ============================================================================

// KnownEntities represents recognized business logic resources and object names.
var KnownEntities = map[string]bool{
	"user": true, "account": true, "profile": true, "member": true, "customer": true, "client": true,
	"order": true, "cart": true, "item": true, "product": true, "transaction": true, "payment": true, "bill": true, "invoice": true, "receipt": true,
	"document": true, "doc": true, "file": true, "attachment": true, "report": true, "upload": true, "image": true, "photo": true, "video": true,
	"ticket": true, "message": true, "chat": true, "comment": true, "post": true, "article": true, "thread": true,
	"tenant": true, "org": true, "organization": true, "company": true, "team": true, "group": true, "role": true, "project": true, "workspace": true,
	"subscription": true, "plan": true, "contract": true, "booking": true, "reservation": true,
	"patient": true, "claim": true, "policy": true, "token": true, "session": true, "device": true, "lead": true,
}

// knownEntities alias for backward compatibility within package scanner.
var knownEntities = KnownEntities

// KnownVerbs maps HTTP/REST action verbs to probable candidate parameter names.
var KnownVerbs = map[string][]string{
	"download": {"file", "path", "filename", "doc_id", "attachment_id", "id"},
	"export":   {"file", "format", "type", "id", "report_id"},
	"view":     {"id", "item_id", "view", "ref"},
	"show":     {"id", "ref", "view"},
	"read":     {"id", "doc_id"},
	"fetch":    {"id", "key", "ref"},
	"get":      {"id", "ref"},
	"edit":     {"id", "item_id", "target"},
	"update":   {"id", "item_id"},
	"delete":   {"id", "item_id", "target", "uid"},
	"remove":   {"id", "item_id"},
	"cancel":   {"id", "order_id", "txn_id"},
	"search":   {"q", "query", "search", "keyword", "term", "filter", "by"},
	"find":     {"q", "query", "keyword", "term"},
	"filter":   {"filter", "by", "category", "status", "type"},
	"list":     {"page", "limit", "offset", "sort", "order", "status"},
	"redirect": {"url", "redirect", "redirect_url", "return_url", "next", "dest"},
	"forward":  {"url", "dest", "to"},
	"goto":     {"url", "target", "next"},
	"return":   {"return_url", "url", "next"},
	"auth":     {"token", "code", "key", "user_id", "session_id", "auth"},
	"verify":   {"token", "code", "key", "id", "hash"},
	"reset":    {"token", "code", "key", "email", "id"},
	"login":    {"username", "user", "email", "password", "redirect"},
	"register": {"username", "user", "email", "role", "plan"},
}

// knownVerbs alias for backward compatibility within package scanner.
var knownVerbs = KnownVerbs

// ============================================================================
// Vendor & Asset Wordlists
// ============================================================================

// VendorJSLibraries lists known third-party UI/JS frameworks to filter internal dictionary noise.
var VendorJSLibraries = []string{
	"bootstrap", "jquery", "popper", "react", "vue", "angular",
	"lodash", "moment", "fontawesome", "swiper", "select2",
	"chart.min.js", "chart.js", "core-js", "polyfill", "modernizr",
	"materialize", "semantic", "foundation", "uikit", "alpine",
}

// StaticAssetDirs lists common directory paths holding static assets rather than API routes.
var StaticAssetDirs = []string{
	"/css/", "/js/", "/images/", "/image/", "/img/", "/fonts/", "/font/",
	"/assets/", "/static/", "/dist/", "/vendor/", "/locales/", "/media/",
}

// StaticFileExtensions contains file extensions that represent static media or client assets.
var StaticFileExtensions = map[string]bool{
	".css": true, ".js": true, ".png": true, ".jpg": true, ".jpeg": true,
	".gif": true, ".svg": true, ".ico": true, ".woff": true, ".woff2": true,
	".ttf": true, ".eot": true, ".map": true, ".txt": true, ".pdf": true,
	".zip": true, ".tar": true, ".gz": true, ".xml": true, ".mp4": true,
}
