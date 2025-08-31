package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
	config "user_service/firebase"
	"user_service/middleware"
	"user_service/models"

	firebase "firebase.google.com/go/v4"
)

func getUID(r *http.Request) string {
	return r.Context().Value(middleware.UIDKey).(string)
}

// GetProfile fetches /users/{uid}
func GetProfile(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := getUID(r)
		db, _ := app.Database(context.Background())
		ref := db.NewRef("/users/" + uid)

		var profile models.UserProfile
		if err := ref.Get(r.Context(), &profile); err != nil {
			http.Error(w, "failed to fetch profile", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(profile)
	}
}

// Ledger returns a consolidated view of scan credits, credit lots (FIFO by expiry),
// and purchase history for the authenticated user at /users/{uid}.
func GetLedger(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		uid := getUID(r)

		db, err := app.Database(ctx)
		if err != nil {
			http.Error(w, "database init error", http.StatusInternalServerError)
			return
		}

		type lotOut struct {
			ID               string `json:"id"`
			Plan             string `json:"plan,omitempty"`
			TotalCredits     int    `json:"total_credits,omitempty"`
			RemainingCredits int    `json:"remaining_credits"`
			PurchasedAt      string `json:"purchased_at,omitempty"`
			ExpiresAt        string `json:"expires_at,omitempty"`
			Status           string `json:"status,omitempty"`
			OrderID          string `json:"order_id,omitempty"`
			PaypalID         string `json:"paypal_id,omitempty"`
			PriceUSD         string `json:"price_usd,omitempty"`
		}
		type purchaseOut struct {
			ID          string `json:"id"`
			Plan        string `json:"plan,omitempty"`
			Credits     int    `json:"credits"`
			PurchasedAt string `json:"purchased_at,omitempty"`
			ExpiresAt   string `json:"expires_at,omitempty"`
			Status      string `json:"status,omitempty"`
			OrderID     string `json:"order_id,omitempty"`
			PaypalID    string `json:"paypal_id,omitempty"`
			PriceUSD    string `json:"price_usd,omitempty"`
		}
		type resp struct {
			CreditsAvailable      int           `json:"credits_available"`
			ScanCount             int           `json:"scan_count"`
			TotalRemainingCredits int           `json:"total_remaining_credits"`
			NextExpiry            string        `json:"next_expiry,omitempty"`
			CreditLots            []lotOut      `json:"credit_lots"`
			Purchases             []purchaseOut `json:"purchases"`
		}

		asInt := func(v interface{}) int {
			switch x := v.(type) {
			case int:
				return x
			case int64:
				return int(x)
			case float64:
				return int(x)
			default:
				return 0
			}
		}
		asString := func(v interface{}) string {
			if s, ok := v.(string); ok {
				return s
			}
			return ""
		}

		// --- read credits_available & scanCount ---
		var creditsAvailF, scanCountF float64
		_ = db.NewRef("/users/"+uid+"/credits_available").Get(ctx, &creditsAvailF)
		_ = db.NewRef("/users/"+uid+"/scanCount").Get(ctx, &scanCountF)
		creditsAvailable := int(creditsAvailF)
		simpleScanCount := int(scanCountF)

		// --- read credit lots ---
		var lotsRaw map[string]map[string]interface{}
		_ = db.NewRef("/users/"+uid+"/credit_lots").Get(ctx, &lotsRaw)

		lots := make([]lotOut, 0, len(lotsRaw))
		totalRemaining := 0
		var nextExpiry *time.Time

		for id, m := range lotsRaw {
			lo := lotOut{
				ID:               id,
				Plan:             asString(m["plan"]),
				TotalCredits:     asInt(m["total_credits"]),
				RemainingCredits: asInt(m["remaining_credits"]),
				PurchasedAt:      asString(m["purchased_at"]),
				ExpiresAt:        asString(m["expires_at"]),
				Status:           strings.ToUpper(asString(m["status"])),
				OrderID:          asString(m["order_id"]),
				PaypalID:         asString(m["paypal_id"]),
				PriceUSD:         asString(m["price_usd"]),
			}
			totalRemaining += lo.RemainingCredits
			// Track earliest upcoming expiry among non-depleted lots
			if lo.RemainingCredits > 0 && lo.ExpiresAt != "" {
				if t, err := time.Parse(time.RFC3339, lo.ExpiresAt); err == nil {
					if nextExpiry == nil || t.Before(*nextExpiry) {
						tmp := t
						nextExpiry = &tmp
					}
				}
			}
			lots = append(lots, lo)
		}

		// sort lots by earliest expiry first (nil/invalid expiry goes last)
		sort.Slice(lots, func(i, j int) bool {
			ti, ei := time.Parse(time.RFC3339, lots[i].ExpiresAt)
			tj, ej := time.Parse(time.RFC3339, lots[j].ExpiresAt)
			if ei != nil && ej != nil {
				return lots[i].ID < lots[j].ID
			}
			if ei != nil {
				return false
			}
			if ej != nil {
				return true
			}
			return ti.Before(tj)
		})

		// --- read purchases (/subscriptions/{uid}/{key}) ---
		var subsRaw map[string]map[string]interface{}
		_ = db.NewRef("/subscriptions/"+uid).Get(ctx, &subsRaw)

		purchases := make([]purchaseOut, 0, len(subsRaw))
		for id, m := range subsRaw {
			p := purchaseOut{
				ID:          id,
				Plan:        asString(m["plan"]),
				Credits:     asInt(m["credits"]),
				PurchasedAt: asString(m["purchased_at"]),
				ExpiresAt:   asString(m["expires_at"]),
				Status:      strings.ToUpper(asString(m["status"])),
				OrderID:     asString(m["order_id"]),
				PaypalID:    asString(m["paypal_id"]),
				PriceUSD:    asString(m["price_usd"]),
			}
			purchases = append(purchases, p)
		}
		// newest purchase first
		sort.Slice(purchases, func(i, j int) bool {
			ti, ei := time.Parse(time.RFC3339, purchases[i].PurchasedAt)
			tj, ej := time.Parse(time.RFC3339, purchases[j].PurchasedAt)
			if ei != nil && ej != nil {
				return purchases[i].ID > purchases[j].ID
			}
			if ei != nil {
				return false
			}
			if ej != nil {
				return true
			}
			return tj.Before(ti)
		})

		out := resp{
			CreditsAvailable:      creditsAvailable,
			ScanCount:             simpleScanCount,
			TotalRemainingCredits: totalRemaining,
			CreditLots:            lots,
			Purchases:             purchases,
		}
		if nextExpiry != nil {
			out.NextExpiry = nextExpiry.Format(time.RFC3339)
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	}
}

// GetUsage returns only usage_count
func GetUsage(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := getUID(r)
		db, _ := app.Database(context.Background())
		var usage int
		db.NewRef("/users/"+uid+"/usage_count").Get(r.Context(), &usage)
		json.NewEncoder(w).Encode(map[string]int{"usage_count": usage})
	}
}

// IncrementUsage bumps usage_count by 1
func IncrementUsage(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := getUID(r)
		db, _ := app.Database(context.Background())

		ref := db.NewRef("/users/" + uid + "/usage_count")
		var current int
		ref.Get(r.Context(), &current)
		ref.Set(r.Context(), current+1)

		json.NewEncoder(w).Encode(map[string]int{"usage_count": current + 1})
	}
}

// GetPlan reads /subscriptions/{uid}
func GetPlan(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := getUID(r)
		db, _ := app.Database(context.Background())
		ref := db.NewRef("/subscriptions/" + uid)

		var sub models.Subscription
		if err := ref.Get(r.Context(), &sub); err != nil {
			http.Error(w, "failed to fetch subscription", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(sub)
	}
}

// UpdatePlan sets/updates plan info
func UpdatePlan(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uid := getUID(r)
		var req struct {
			Plan       string    `json:"plan"`
			RazorpayID string    `json:"razorpay_id"`
			ExpiresAt  time.Time `json:"expires_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			return
		}

		db, _ := app.Database(context.Background())
		ref := db.NewRef("/subscriptions/" + uid)
		sub := models.Subscription{
			Plan:        req.Plan,
			PurchasedAt: time.Now(),
			ExpiresAt:   req.ExpiresAt,
			RazorpayID:  req.RazorpayID,
		}
		if err := ref.Set(r.Context(), sub); err != nil {
			http.Error(w, "failed to update subscription", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(sub)
	}
}

// ScanSummary is the lightweight info returned when details are requested.
type ScanSummary struct {
	ScanID      string      `json:"scan_id"`
	Score       interface{} `json:"score,omitempty"`
	Status      interface{} `json:"status,omitempty"`
	CreatedAt   interface{} `json:"created_at,omitempty"`
	CompletedAt interface{} `json:"completed_at,omitempty"`
	URL         interface{} `json:"url,omitempty"`
	Platform    interface{} `json:"platform,omitempty"`
}

// UserScansResult is the aggregate result.
type UserScansResult struct {
	UserID      string        `json:"user_id"`
	ScanIDs     []string      `json:"scan_ids"`
	Scans       []ScanSummary `json:"scans,omitempty"`
	FailedFetch []string      `json:"failed_summaries,omitempty"` // optional: which scan summaries failed
}

// GetUserScanIDs fetches all scan IDs indexed under users/{userId}/scans
func GetUserScanIDs(ctx context.Context, userId string) ([]string, error) {
	if strings.TrimSpace(userId) == "" {
		return nil, fmt.Errorf("userId is required")
	}

	userScansRef := config.DB.NewRef(fmt.Sprintf("users/%s/scans", userId))

	var scansMap map[string]interface{}
	if err := userScansRef.Get(ctx, &scansMap); err != nil {
		return nil, fmt.Errorf("failed to read user scans: %w", err)
	}

	if scansMap == nil {
		return []string{}, nil
	}

	scanIDs := make([]string, 0, len(scansMap))
	for scanID := range scansMap {
		scanIDs = append(scanIDs, scanID)
	}
	return scanIDs, nil
}

// GetMyScansHandler returns scans for the authenticated user (uses UID from context).
func GetMyScansHandler(app *firebase.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		uid := getUID(r)
		if strings.TrimSpace(uid) == "" {
			http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
			return
		}

		db, _ := app.Database(r.Context())

		// Fetch scan IDs indexed under /users/{uid}/scans
		userScansRef := db.NewRef(fmt.Sprintf("users/%s/scans", uid))
		var scansMap map[string]interface{}
		if err := userScansRef.Get(r.Context(), &scansMap); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"failed to read user scans: %s"}`, err.Error()), http.StatusInternalServerError)
			return
		}
		scanIDs := make([]string, 0)
		if scansMap != nil {
			for scanID := range scansMap {
				scanIDs = append(scanIDs, scanID)
			}
		}

		// Determine if details should be included
		detailsParam := r.URL.Query().Get("details")
		includeDetails := detailsParam == "1" || strings.ToLower(detailsParam) == "true"

		resp := map[string]interface{}{
			"user_id":  uid,
			"scan_ids": scanIDs,
		}

		if !includeDetails || len(scanIDs) == 0 {
			json.NewEncoder(w).Encode(resp)
			return
		}

		// Fetch lightweight summaries with bounded concurrency
		type ScanSummary struct {
			ScanID      string      `json:"scan_id"`
			Score       interface{} `json:"score,omitempty"`
			Status      interface{} `json:"status,omitempty"`
			CreatedAt   interface{} `json:"created_at,omitempty"`
			CompletedAt interface{} `json:"completed_at,omitempty"`
			URL         interface{} `json:"url,omitempty"`
			Platform    interface{} `json:"platform,omitempty"`
		}

		var (
			mu          sync.Mutex
			wg          sync.WaitGroup
			concurrency = 5
			sem         = make(chan struct{}, concurrency)
			summaries   = make([]ScanSummary, 0, len(scanIDs))
			failed      = make([]string, 0)
		)

		for _, scanID := range scanIDs {
			wg.Add(1)
			go func(sid string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				scanRef := db.NewRef(fmt.Sprintf("scans/%s", sid))
				var scanMeta map[string]interface{}
				if err := scanRef.Get(r.Context(), &scanMeta); err != nil {
					log.Printf("warning: failed to fetch scan %s: %v", sid, err)
					mu.Lock()
					failed = append(failed, sid)
					mu.Unlock()
					return
				}

				summary := ScanSummary{
					ScanID: sid,
				}
				if v, ok := scanMeta["score"]; ok {
					summary.Score = v
				}
				if v, ok := scanMeta["status"]; ok {
					summary.Status = v
				}
				if v, ok := scanMeta["created_at"]; ok {
					summary.CreatedAt = v
				}
				if v, ok := scanMeta["completed_at"]; ok {
					summary.CompletedAt = v
				}
				if v, ok := scanMeta["url"]; ok {
					if us, ok2 := v.(string); ok2 {
						summary.URL = us
					} else {
						summary.URL = v
					}
				}
				if v, ok := scanMeta["platform"]; ok {
					summary.Platform = v
				}

				mu.Lock()
				summaries = append(summaries, summary)
				mu.Unlock()
			}(scanID)
		}

		wg.Wait()

		resp["scans"] = summaries
		if len(failed) > 0 {
			resp["failed_summaries"] = failed
		}

		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, `{"error":"failed to serialize response"}`, http.StatusInternalServerError)
			return
		}
	}
}
