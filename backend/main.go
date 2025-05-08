package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"

	_ "github.com/mattn/go-sqlite3"
)

type Service struct {
	ID         string `json:"id"`
	Domain     string `json:"domain"`
	ServiceURL string `json:"serviceUrl"`
	Active     bool   `json:"active"`
	SSL        bool   `json:"ssl"`
}

var (
	db           *sql.DB
	nginxConfDir = "../nginx/conf.d"
	templateDir  = "../nginx/templates"
	sslCertsDir  = "/etc/letsencrypt/live" // Default location for Let's Encrypt certificates
	dbPath       = "/data/services.db"     // Path to the SQLite database in the Docker container
)

func main() {
	// Initialize SQLite database
	initDB()
	defer db.Close()

	// Setup CORS middleware
	handler := corsMiddleware(setupRoutes())

	fmt.Println("Server berjalan pada http://localhost:8081")
	log.Fatal(http.ListenAndServe(":8081", handler))
}
func initDB() {
	var err error
	db, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		log.Fatal(err)
	}

	// Create services table if it doesn't exist
	createTable := `
	CREATE TABLE IF NOT EXISTS services (
		id TEXT PRIMARY KEY,
		domain TEXT UNIQUE NOT NULL,
		service_url TEXT NOT NULL,
		active INTEGER NOT NULL,
		ssl INTEGER NOT NULL DEFAULT 0
	);`

	_, err = db.Exec(createTable)
	if err != nil {
		log.Fatal(err)
	}
}

func setupRoutes() http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/services", handleServices)
	mux.HandleFunc("/api/services/", handleServiceOperation)

	// Serve frontend static files
	fs := http.FileServer(http.Dir("../frontend"))
	mux.Handle("/", fs)

	return mux
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		getServices(w, r)
	case "POST":
		addService(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func handleServiceOperation(w http.ResponseWriter, r *http.Request) {
	// Fix for the "Invalid endpoint" problem
	// Use regex to properly parse the URL path
	togglePattern := regexp.MustCompile(`^/api/services/([^/]+)/toggle$`)
	toggleSSLPattern := regexp.MustCompile(`^/api/services/([^/]+)/togglessl$`)
	deletePattern := regexp.MustCompile(`^/api/services/([^/]+)$`)

	if matches := togglePattern.FindStringSubmatch(r.URL.Path); len(matches) > 1 && r.Method == "POST" {
		// Handle toggle operation
		serviceID := matches[1]
		toggleService(w, r, serviceID)
		return
	} else if matches := toggleSSLPattern.FindStringSubmatch(r.URL.Path); len(matches) > 1 && r.Method == "POST" {
		// Handle toggle SSL operation
		serviceID := matches[1]
		toggleSSL(w, r, serviceID)
		return
	} else if matches := deletePattern.FindStringSubmatch(r.URL.Path); len(matches) > 1 && r.Method == "DELETE" {
		// Handle delete operation
		serviceID := matches[1]
		deleteService(w, r, serviceID)
		return
	}

	http.Error(w, "Invalid endpoint", http.StatusNotFound)
}
func getServices(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query("SELECT id, domain, service_url, active, ssl FROM services")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	services := []Service{}
	for rows.Next() {
		var service Service
		var active, ssl int
		err := rows.Scan(&service.ID, &service.Domain, &service.ServiceURL, &active, &ssl)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		service.Active = active == 1
		service.SSL = ssl == 1
		services = append(services, service)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(services)
}
func addService(w http.ResponseWriter, r *http.Request) {
	var service Service
	if err := json.NewDecoder(r.Body).Decode(&service); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate ID (in production, use UUID)
	var maxID int
	err := db.QueryRow("SELECT COALESCE(MAX(CAST(id AS INTEGER)), 0) FROM services").Scan(&maxID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	service.ID = fmt.Sprintf("%d", maxID+1)
	service.Active = true

	// Insert service into database
	active := 0
	if service.Active {
		active = 1
	}

	ssl := 0
	if service.SSL {
		ssl = 1
	}

	_, err = db.Exec(
		"INSERT INTO services (id, domain, service_url, active, ssl) VALUES (?, ?, ?, ?, ?)",
		service.ID, service.Domain, service.ServiceURL, active, ssl,
	)

	if err != nil {
		// Check for duplicate domain
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			http.Error(w, "Domain already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If SSL is enabled, request SSL certificate
	if service.SSL {
		if err := requestSSLCertificate(service.Domain); err != nil {
			log.Printf("Warning: Failed to request SSL certificate: %v", err)
			// Continue anyway, we don't want to fail the service creation
		}
	}

	// Generate Nginx config
	if err := generateNginxConfig(service); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(service)
}
func deleteService(w http.ResponseWriter, r *http.Request, serviceID string) {
	// Get service to retrieve domain
	var domain string
	err := db.QueryRow("SELECT domain FROM services WHERE id = ?", serviceID).Scan(&domain)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove from database
	_, err = db.Exec("DELETE FROM services WHERE id = ?", serviceID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Remove Nginx config
	configPath := filepath.Join(nginxConfDir, fmt.Sprintf("%s.conf", domain))
	if err := os.Remove(configPath); err != nil && !os.IsNotExist(err) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Reload Nginx to apply changes
	if err := reloadNginx(); err != nil {
		log.Printf("Warning: Failed to reload Nginx: %v", err)
		// Continue anyway, we don't want to fail the service deletion
	}

	w.WriteHeader(http.StatusNoContent)
}
func toggleService(w http.ResponseWriter, r *http.Request, serviceID string) {
	var service Service
	var active, ssl int

	err := db.QueryRow(
		"SELECT id, domain, service_url, active, ssl FROM services WHERE id = ?",
		serviceID,
	).Scan(&service.ID, &service.Domain, &service.ServiceURL, &active, &ssl)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Toggle active status
	service.Active = active != 1
	newActive := 0
	if service.Active {
		newActive = 1
	}

	// Set SSL status
	service.SSL = ssl == 1

	// Update database
	_, err = db.Exec(
		"UPDATE services SET active = ? WHERE id = ?",
		newActive, serviceID,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update Nginx config
	if err := generateNginxConfig(service); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}
func toggleSSL(w http.ResponseWriter, r *http.Request, serviceID string) {
	var service Service
	var active, ssl int

	err := db.QueryRow(
		"SELECT id, domain, service_url, active, ssl FROM services WHERE id = ?",
		serviceID,
	).Scan(&service.ID, &service.Domain, &service.ServiceURL, &active, &ssl)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Service not found", http.StatusNotFound)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Set active status
	service.Active = active == 1

	// Toggle SSL status
	service.SSL = ssl != 1
	newSSL := 0
	if service.SSL {
		newSSL = 1
	}

	// Update database
	_, err = db.Exec(
		"UPDATE services SET ssl = ? WHERE id = ?",
		newSSL, serviceID,
	)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If enabling SSL, request SSL certificate
	if service.SSL {
		if err := requestSSLCertificate(service.Domain); err != nil {
			log.Printf("Warning: Failed to request SSL certificate: %v", err)
			// Continue anyway, we don't want to fail the service update
		}
	}

	// Update Nginx config
	if err := generateNginxConfig(service); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(service)
}
func requestSSLCertificate(domain string) error {
	// For Docker environment, use Certbot in the certbot container
	cmd := exec.Command(
		"docker", "exec", "service-manager-certbot",
		"certbot", "certonly", "--webroot", "-w", "/var/www/certbot",
		"-d", domain, "--non-interactive", "--agree-tos",
		"--email", "admin@example.com", "--expand",
	)

	// If Docker exec fails (when not running in Docker Compose), try direct certbot
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Docker exec failed, trying direct certbot: %v", err)
		cmd = exec.Command(
			"certbot", "certonly", "--nginx",
			"-d", domain, "--non-interactive", "--agree-tos",
			"--email", "admin@example.com",
		)
		output, err = cmd.CombinedOutput()
	}

	if err != nil {
		return fmt.Errorf("certbot error: %v, output: %s", err, output)
	}

	log.Printf("Successfully obtained SSL certificate for %s", domain)
	return nil
}
func generateNginxConfig(service Service) error {
	// Create nginx config directory if it doesn't exist
	if err := os.MkdirAll(nginxConfDir, 0755); err != nil {
		return err
	}

	// Determine which template to use based on SSL status
	templateName := "domain.conf.template"
	if service.SSL {
		templateName = "domain_ssl.conf.template"

		// Check if SSL template exists, fallback to non-SSL if not
		sslTmplPath := filepath.Join(templateDir, templateName)
		if _, err := os.Stat(sslTmplPath); os.IsNotExist(err) {
			log.Printf("Warning: SSL template not found at %s, using non-SSL template", sslTmplPath)
			templateName = "domain.conf.template"
		}
	}

	// Read template
	tmplPath := filepath.Join(templateDir, templateName)
	// Try backup location if primary fails
	if _, err := os.Stat(tmplPath); os.IsNotExist(err) {
		tmplPath = filepath.Join(templateDir, "../../", templateName)
	}

	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		return err
	}

	// Create config file
	configPath := filepath.Join(nginxConfDir, fmt.Sprintf("%s.conf", service.Domain))
	file, err := os.Create(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Execute template
	if err := tmpl.Execute(file, service); err != nil {
		return err
	}

	// Reload Nginx to apply changes
	return reloadNginx()
}
func reloadNginx() error {
	// For Docker environment, use the reload script in Nginx container
	cmd := exec.Command("docker", "exec", "service-manager-nginx", "/usr/local/bin/reload-nginx.sh")
	output, err := cmd.CombinedOutput()

	// If Docker exec fails (when not running in Docker Compose), try direct reload
	if err != nil {
		log.Printf("Docker exec failed, trying direct Nginx reload: %v", err)
		cmd = exec.Command("nginx", "-s", "reload")
		output, err = cmd.CombinedOutput()
	}

	if err != nil {
		return fmt.Errorf("nginx reload error: %v, output: %s", err, output)
	}

	log.Println("Nginx configuration reloaded successfully")
	return nil
}

// func reloadNginxAPI() error {
// 	ctx := context.Background()
// 	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
// 	if err != nil {
// 		return fmt.Errorf("failed to create Docker client: %v", err)
// 	}
// 	defer cli.Close()

// 	// Membuat exec instance
// 	execConfig := types.ExecConfig{
// 		Cmd:          []string{"/usr/local/bin/reload-nginx.sh"},
// 		AttachStdout: true,
// 		AttachStderr: true,
// 	}

// 	execID, err := cli.ContainerExecCreate(ctx, "service-manager-nginx", execConfig)
// 	if err != nil {
// 		return fmt.Errorf("failed to create exec: %v", err)
// 	}

// 	// Menjalankan exec
// 	if err := cli.ContainerExecStart(ctx, execID.ID, types.ExecStartCheck{}); err != nil {
// 		return fmt.Errorf("failed to start exec: %v", err)
// 	}

// 	log.Println("Nginx configuration reloaded successfully")
// 	return nil
// }
