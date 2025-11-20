package main

import (
  "log"
  "net/http"
)

func main() {
  http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    w.Write([]byte(`{"status":"ok"}`))
  })
  log.Println("🚀 Core Service started on :8080")
  log.Fatal(http.ListenAndServe(":8080", nil))
}
