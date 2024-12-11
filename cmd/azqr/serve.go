// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

package azqr

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Azure/azqr/internal"
	"github.com/Azure/azqr/internal/azqr"
	"github.com/Azure/azqr/internal/scanners"
	"github.com/google/uuid"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	serveCmd.PersistentFlags().Int("port", 8080, "Port to listen to")

	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Scan Azure Resources",
	Long:  "Scan Azure Resources",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		serviceScanners := scanners.GetScanners()
		serve(cmd, serviceScanners)
	},
}

func serve(cmd *cobra.Command, serviceScanners []azqr.IAzureScanner) {
	port, _ := cmd.Flags().GetInt("port")

	r := mux.NewRouter()
	api := r.PathPrefix("/api/").Subrouter()
	api.HandleFunc("/healthz", getHealthHandler).Methods("GET")
	api.HandleFunc("/scan", runScanHandler).Methods("POST")
	api.HandleFunc("/scans/{id}", getScanHandler).Methods("GET")

	spa := spaHandler{staticPath: "web/dist", indexPath: "index.html"}
	r.PathPrefix("/").Handler(spa)

	srv := &http.Server{
		Handler:      r,
		Addr:         fmt.Sprintf("0.0.0.0:%v", port),
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}
	log.Info().Msgf("azqr server running on http://localhost:%v\n", port)
	log.Fatal().Err(srv.ListenAndServe()).Msg("Failed to start server")
}

var upgrader = websocket.Upgrader{} // use default options

var epoch = time.Unix(0, 0).Format(time.RFC1123)

var noCacheHeaders = map[string]string{
	"Expires":         epoch,
	"Cache-Control":   "no-cache, private, max-age=0",
	"Pragma":          "no-cache",
	"X-Accel-Expires": "0",
}

var etagHeaders = []string{
	"ETag",
	"If-Modified-Since",
	"If-Match",
	"If-None-Match",
	"If-Range",
	"If-Unmodified-Since",
}

// spaHandler implements the http.Handler interface, so we can use it
// to respond to HTTP requests. The path to the static directory and
// path to the index file within that static directory are used to
// serve the SPA in the given static directory.
type spaHandler struct {
	staticPath string
	indexPath  string
}

// ServeHTTP inspects the URL path to locate a file within the static dir
// on the SPA handler. If a file is found, it will be served. If not, the
// file located at the index path on the SPA handler will be served. This
// is suitable behavior for serving an SPA (single page application).
func (h spaHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get the absolute path to prevent directory traversal
	path, err := filepath.Abs(r.URL.Path)
	log.Info().Msgf("path: %s", path)
	if err != nil {
		// if we failed to get the absolute path respond with a 400 bad request
		// and stop
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// get the volume of the absolute path and remove it
	volume := filepath.VolumeName(path)
	resourcePath := strings.Replace(path, volume, "", 1)

	// prepend the path with the path to the static directory
	resourcePath = filepath.Join(h.staticPath, resourcePath)
	log.Info().Msgf("resourcePath: %s", resourcePath)

	baseHref, hasCustomBaseHref := os.LookupEnv("SERVER_BASE_HREF")

	// check whether a file exists at the given path
	_, err = os.Stat(resourcePath)
	if os.IsNotExist(err) {
		// file does not exist, serve index.html

		if hasCustomBaseHref {
			generateIndexFile(w, r, baseHref)
		} else {
			http.ServeFile(w, r, filepath.Join(h.staticPath, h.indexPath))
		}

		return
	} else if err != nil {
		// if we got an error (that wasn't that the file doesn't exist) stating the
		// file, return a 500 internal server error and stop
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if hasCustomBaseHref && (strings.HasSuffix(path, "index.html") || strings.HasSuffix(path, "/")) {
		generateIndexFile(w, r, baseHref)
		return
	}

	// otherwise, use http.FileServer to serve the static dir
	noCache(http.StripPrefix("/", http.FileServer(http.Dir(h.staticPath)))).ServeHTTP(w, r)
}

func generateIndexFile(w http.ResponseWriter, r *http.Request, baseHref string) {
	path, _ := os.Getwd()
	buf, err := os.ReadFile(filepath.Join(path, "/web/dist/index.html"))
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}

	file := string(buf)
	file = strings.Replace(file, `<base href="/">`, fmt.Sprintf(`<base href="%s">`, baseHref), 1)
	respondWithHtml(w, 200, file)
}

func respondWithHtml(w http.ResponseWriter, code int, payload string) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(code)
	_, err := w.Write(([]byte(payload)))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func respondWithError(w http.ResponseWriter, code int, message string) {
	respondWithJSON(w, code, map[string]string{"error": message})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	response, _ := json.Marshal(payload)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, err := w.Write(response)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func noCache(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		// Delete any ETag headers that may have been set
		for _, v := range etagHeaders {
			if r.Header.Get(v) != "" {
				r.Header.Del(v)
			}
		}

		// Set our NoCache headers
		for k, v := range noCacheHeaders {
			w.Header().Set(k, v)
		}

		h.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func getScanHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]

	// TODO: Add logic to retrieve the scan result by ID

	respondWithJSON(w, 200, id)
}

func getHealthHandler(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, 200, "OK")
}

func runScanHandler(w http.ResponseWriter, r *http.Request) {
	params := internal.NewScanParams()

	err := json.NewDecoder(r.Body).Decode(params)
	if err != nil {
		respondWithError(w, http.StatusBadRequest, "Invalid request payload")
		return
	}

	// Here you would add the logic to initiate the scan using the parameters
	// For now, we'll just return a success message with a dummy scan ID
	scanID := uuid.New().String()

	go func() {
		params.Debug = false
		params.ServiceScanners = scanners.GetScanners()
		scanner := internal.Scanner{}
		scanner.Scan(params)
	}()

	response := map[string]string{
		"message":    "azqr scan initiated successfully",
		"status":     "running",
		"status_url": fmt.Sprintf("http://localhost:%d/api/scans/%s", 8080, scanID),
		"started_at": time.Now().Format(time.RFC3339),
		"scan_id":    scanID,
	}
	respondWithJSON(w, http.StatusOK, response)
}
