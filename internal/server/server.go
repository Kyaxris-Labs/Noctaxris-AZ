package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/amqp"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/azerrors"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/config"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/audit"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authn"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/authz"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/kernel/tlsutil"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/store"
	"github.com/Kyaxris-Labs/Noctaxris-AZ/internal/version"
)

const (
	healthPath      = "/_noctaxris-az/health"
	readyPath       = "/_noctaxris-az/ready"
	versionPath     = "/_noctaxris-az/version"
	requestIDHeader = "X-Request-Id"
	shutdownTimeout = 10 * time.Second
)

type ctxKey int

const ctxRequestID ctxKey = 1

// Server is the HTTP listener for Noctaxris-AZ.
type Server struct {
	cfg           config.Config
	store         *store.Store
	audit         *audit.Writer
	authn         *authn.Authenticator
	authz         *authz.Evaluator
	mux           *http.ServeMux
	clockMu       sync.RWMutex
	clockOverride *time.Time
}

// New builds a Server with health routes and service mounts.
func New(cfg config.Config, st *store.Store, aud *audit.Writer) *Server {
	s := &Server{
		cfg:   cfg,
		store: st,
		audit: aud,
		authn: &authn.Authenticator{
			RootClientID:    cfg.RootClientID,
			RootAccessToken: cfg.RootAccessToken,
			Tokens:          st,
		},
		authz: &authz.Evaluator{Assignments: st},
		mux:   http.NewServeMux(),
	}
	s.registerREST()
	s.registerIdentity()
	s.registerData()
	s.registerNetwork()
	s.registerApp()
	s.registerEdge()
	s.registerObserve()
	s.registerLabForensics()
	return s
}

// Authz returns the RBAC evaluator for handlers.
func (s *Server) Authz() *authz.Evaluator { return s.authz }

// PrincipalFromContext returns the authenticated principal when present.
func PrincipalFromContext(ctx context.Context) (authn.Principal, bool) {
	return authn.PrincipalFromContext(ctx)
}

// RequestIDFromContext returns the request id when present.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(ctxRequestID).(string)
	return id
}

func (s *Server) registerREST() {
	s.mux.HandleFunc(healthPath, s.handleHealth)
	s.mux.HandleFunc(readyPath, s.handleReady)
	s.mux.HandleFunc(versionPath, s.handleVersion)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		azerrors.BadRequest(w, "method not allowed")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		azerrors.BadRequest(w, "method not allowed")
		return
	}
	if s.store == nil {
		azerrors.WriteARM(w, http.StatusServiceUnavailable, "ServiceUnavailable", "store not ready")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleVersion(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		azerrors.BadRequest(w, "method not allowed")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"version": version.Version})
}

// Handler returns the HTTP handler with auth middleware.
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get(requestIDHeader)
		if reqID == "" {
			reqID = newRequestID()
		}
		w.Header().Set(requestIDHeader, reqID)
		ctx := context.WithValue(r.Context(), ctxRequestID, reqID)
		r = r.WithContext(ctx)
		if p := canonicalizeARMPath(r.URL.Path); p != r.URL.Path {
			u := *r.URL
			u.Path = p
			u.RawPath = ""
			r = r.Clone(ctx)
			r.URL = &u
		}

		if authn.IsPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		path := r.URL.Path
		if strings.HasPrefix(path, "/blob/") || strings.HasPrefix(path, "/queue/") || strings.HasPrefix(path, "/table/") {
			authzHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authzHeader, "SharedKey") || authn.HasSAS(r) {
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}

		p, err := s.authn.AuthenticateRequest(r)
		if err != nil {
			if errors.Is(err, authn.ErrUnauthenticated) {
				azerrors.Unauthenticated(w, "")
				return
			}
			azerrors.WriteARM(w, http.StatusInternalServerError, "InternalServerError", err.Error())
			return
		}
		ctx = authn.WithPrincipal(ctx, p)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// StartAMQP starts the AMQP 1.0 lite listener in the background.
func (s *Server) StartAMQP(ctx context.Context) error {
	addr := s.cfg.AMQPListenAddr
	go func() {
		_ = amqp.Start(ctx, addr, s.store)
	}()
	return nil
}

// ListenAndServeContext serves until ctx is cancelled, then drains with a timeout.
func (s *Server) ListenAndServeContext(ctx context.Context) error {
	handler := s.Handler()
	main := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errCh := make(chan error, 2)
	go func() {
		var err error
		if s.cfg.TLSEnabled() {
			err = main.ListenAndServeTLS(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		} else {
			err = main.ListenAndServe()
		}
		errCh <- err
	}()

	var cloud *http.Server
	if s.cfg.CloudHosts {
		secretsDir := filepath.Dir(store.DefaultMasterKeyPath(s.cfg.DataRoot))
		if s.cfg.MasterKeyPath != "" {
			secretsDir = filepath.Dir(s.cfg.MasterKeyPath)
		}
		paths, err := tlsutil.EnsureServerCert(secretsDir, time.Time{})
		if err != nil {
			return fmt.Errorf("cloud-hosts cert: %w", err)
		}
		tlsCfg, err := tlsutil.LoadTLSConfig(paths)
		if err != nil {
			return err
		}
		cloud = &http.Server{
			Addr:              s.cfg.CloudHostsListen,
			Handler:           handler,
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 10 * time.Second,
		}
		go func() {
			errCh <- cloud.ListenAndServeTLS(paths.ServerCert, paths.ServerKey)
		}()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = main.Shutdown(shutdownCtx)
		if cloud != nil {
			_ = cloud.Shutdown(shutdownCtx)
		}
		err := <-errCh
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
