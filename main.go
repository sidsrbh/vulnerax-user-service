package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	firebase "user_service/firebase"
	"user_service/handlers"
	"user_service/middleware"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/rs/cors"
)

func main() {
	// load .env (optional)
	if err := godotenv.Load(); err != nil {
		log.Println("no .env, falling back to environment variables")
	}

	// initialize Firebase app (assumes firebase.Init() does necessary init and returns the app)
	firebase.Init()
	fbApp := firebase.App
	// router
	r := mux.NewRouter()

	// protected /api/user/* routes
	userGroup := r.PathPrefix("/api/user").Subrouter()
	userGroup.Use(middleware.VerifyFirebaseToken(fbApp))
	userGroup.HandleFunc("/profile", handlers.GetProfile(fbApp)).Methods("GET")
	userGroup.HandleFunc("/usage", handlers.GetUsage(fbApp)).Methods("GET")
	userGroup.HandleFunc("/usage/increment", handlers.IncrementUsage(fbApp)).Methods("POST")
	userGroup.HandleFunc("/plan", handlers.GetPlan(fbApp)).Methods("GET")
	userGroup.HandleFunc("/plan/update", handlers.UpdatePlan(fbApp)).Methods("POST")
	userGroup.HandleFunc("/scans", handlers.GetMyScansHandler(fbApp)).Methods("GET")
	userGroup.HandleFunc("/ledger", handlers.GetLedger(fbApp)).Methods("GET")

	// CORS configuration
	frontendOrigin := os.Getenv("FRONTEND_ORIGIN")
	if frontendOrigin == "" {
		frontendOrigin = "*"
	}

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{frontendOrigin}, // cannot be "*" if AllowCredentials=true
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Origin", "Content-Type", "Authorization"},
		ExposedHeaders:   []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           int((12 * time.Hour).Seconds()),
	})

	// wrap router with CORS handler
	handler := c.Handler(r)

	// port normalization
	// port normalization (prefer Cloud Run's PORT)
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	// create HTTP server with timeouts
	srv := &http.Server{
		Addr:         port,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("user service listening on %s (allowing CORS from %s)", port, frontendOrigin)
	log.Fatal(srv.ListenAndServe())
}
