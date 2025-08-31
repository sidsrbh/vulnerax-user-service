package config

import (
	"context"
	"log"
	"os"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/db"
	"firebase.google.com/go/v4/storage"
	"google.golang.org/api/option"
)

var App *firebase.App
var DB *db.Client
var Storage *storage.Client

func Init() {
	ctx := context.Background()

	// Load Firebase credentials
	credFile := os.Getenv("FIREBASE_CREDENTIALS")
	if credFile == "" {
		log.Fatal("FIREBASE_CREDENTIALS environment variable not set")
	}
	opt := option.WithCredentialsFile(credFile)

	conf := &firebase.Config{
		DatabaseURL:   os.Getenv("FIREBASE_DB_URL"),
		StorageBucket: os.Getenv("FIREBASE_STORAGE_BUCKET"),
	}

	app, err := firebase.NewApp(ctx, conf, opt)
	if err != nil {
		log.Fatalf("Firebase init error: %v", err)
	}
	App = app

	// Initialize Realtime Database
	dbClient, err := app.Database(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize Firebase Realtime Database client: %v", err)
	}
	DB = dbClient

	// Initialize Firebase Storage
	storageClient, err := app.Storage(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize Firebase Storage client: %v", err)
	}
	Storage = storageClient

	log.Println("Firebase initialized successfully")
}
