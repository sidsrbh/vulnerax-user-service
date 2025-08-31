package middleware

import (
	"context"
	"net/http"
	"strings"

	firebase "firebase.google.com/go/v4"
)

type contextKey string

const UIDKey contextKey = "uid"

// VerifyFirebaseToken returns a middleware that checks
// “Authorization: Bearer <idToken>” against Firebase Auth.
func VerifyFirebaseToken(app *firebase.App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			idToken := strings.TrimPrefix(header, "Bearer ")

			client, err := app.Auth(context.Background())
			if err != nil {
				http.Error(w, "auth init error", http.StatusInternalServerError)
				return
			}
			tok, err := client.VerifyIDToken(context.Background(), idToken)
			if err != nil {
				http.Error(w, "invalid token", http.StatusUnauthorized)
				return
			}

			// pass UID in context
			ctx := context.WithValue(r.Context(), UIDKey, tok.UID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}
