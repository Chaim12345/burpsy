package vulnapp

// Race-condition fixtures (burpsy-react-ui-0vzb.8), for internal/scanner/checks_race.go.
//
// The vulnerable endpoint models a single-use coupon redemption written as check-then-set: it
// reads the coupon's redeemed flag, answers "already redeemed" when it is set, and only then
// records the redemption — with a 50ms gap between the check and the set. That gap is the window
// a synchronized group walks through: every member passes the check before any member's record
// lands, so one coupon redeems once per member. Sent one request at a time the same endpoint
// redeems exactly once. The safe twin holds the lock across the check and the set, so the same
// group wins exactly once however it arrives.

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

var raceRedeemed = struct {
	sync.Mutex
	used map[string]bool
}{used: map[string]bool{}}

// raceRedeem serves one coupon-redemption attempt. safe holds the lock across the check and the
// record; !safe checks, sleeps inside the window, then records.
func raceRedeem(w http.ResponseWriter, r *http.Request, safe bool) {
	coupon := r.URL.Query().Get("coupon")
	if coupon == "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"coupon required"}`))
		return
	}
	if safe {
		raceRedeemed.Lock()
		already := raceRedeemed.used[coupon]
		if !already {
			raceRedeemed.used[coupon] = true
		}
		raceRedeemed.Unlock()
		raceRedeemAnswer(w, coupon, already)
		return
	}
	raceRedeemed.Lock()
	already := raceRedeemed.used[coupon]
	raceRedeemed.Unlock()
	if already {
		raceRedeemAnswer(w, coupon, true)
		return
	}
	// The vulnerable window: the check passed and the record happens later, so a group that
	// started together all passes the check before any member's record lands.
	time.Sleep(50 * time.Millisecond)
	raceRedeemed.Lock()
	raceRedeemed.used[coupon] = true
	raceRedeemed.Unlock()
	raceRedeemAnswer(w, coupon, false)
}

func raceRedeemAnswer(w http.ResponseWriter, coupon string, already bool) {
	w.Header().Set("Content-Type", "application/json")
	if already {
		w.WriteHeader(http.StatusConflict)
		_, _ = fmt.Fprintf(w, `{"coupon":%q,"redeemed":false,"error":"already redeemed"}`, coupon)
		return
	}
	_, _ = fmt.Fprintf(w, `{"coupon":%q,"redeemed":true}`, coupon)
}

func raceEndpoints() []Endpoint {
	return []Endpoint{
		{Path: "/race/redeem?coupon=welcome", Method: http.MethodPost, Row: "Race condition (single-packet)",
			Note: "single-use coupon redemption written check-then-set, a 50ms window between the check and the record"},
		{Path: "/race/safe/redeem?coupon=welcome", Method: http.MethodPost, Row: "Race condition (single-packet)",
			Safe: true,
			Note: "the same redemption holding the lock across the check and the set"},
	}
}

func registerRace(mux *http.ServeMux) {
	mux.HandleFunc("/race/redeem", func(w http.ResponseWriter, r *http.Request) { raceRedeem(w, r, false) })
	mux.HandleFunc("/race/safe/redeem", func(w http.ResponseWriter, r *http.Request) { raceRedeem(w, r, true) })
}
