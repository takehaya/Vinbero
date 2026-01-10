package server

import (
	"context"
	"fmt"
	"net/http"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/takehaya/vinbero/api/vinbero/v1/vinberov1connect"
	"github.com/takehaya/vinbero/pkg/bpf"
	"github.com/takehaya/vinbero/pkg/config"
)

// Server represents the Connect RPC server
type Server struct {
	cfg    *config.Config
	mapOps *bpf.MapOperations
	logger *zap.Logger
	mux    *http.ServeMux
	server *http.Server
}

// NewServer creates a new Server instance
func NewServer(cfg *config.Config, mapOps *bpf.MapOperations, logger *zap.Logger) *Server {
	return &Server{
		cfg:    cfg,
		mapOps: mapOps,
		logger: logger,
		mux:    http.NewServeMux(),
	}
}

// Setup registers all service handlers
func (s *Server) Setup() {
	// SidFunction service
	sidFunctionServer := NewSidFunctionServer(s.mapOps)
	path, handler := vinberov1connect.NewSidFunctionServiceHandler(sidFunctionServer)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered SidFunctionService", zap.String("path", path))

	// Transitv4 service
	transitv4Server := NewTransitv4Server(s.mapOps)
	path, handler = vinberov1connect.NewTransitv4ServiceHandler(transitv4Server)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered Transitv4Service", zap.String("path", path))

	// Transitv6 service
	transitv6Server := NewTransitv6Server(s.mapOps)
	path, handler = vinberov1connect.NewTransitv6ServiceHandler(transitv6Server)
	s.mux.Handle(path, handler)
	s.logger.Info("Registered Transitv6Service", zap.String("path", path))

	// Health check endpoint
	s.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := s.cfg.InternalConfig.Server.BindAddress
	s.server = &http.Server{
		Addr: addr,
		// Use h2c to support HTTP/2 without TLS (required for gRPC)
		Handler: h2c.NewHandler(s.mux, &http2.Server{}),
	}

	s.logger.Info("Starting Connect RPC server", zap.String("address", addr))
	return s.server.ListenAndServe()
}

// Shutdown gracefully shuts down the server
func (s *Server) Shutdown(ctx context.Context) error {
	if s.server == nil {
		return nil
	}
	s.logger.Info("Shutting down Connect RPC server")
	return s.server.Shutdown(ctx)
}

// ListenAndServe is a convenience method that sets up and starts the server
func (s *Server) ListenAndServe() error {
	s.Setup()
	return s.Start()
}

// Mux returns the underlying http.ServeMux for custom handler registration
func (s *Server) Mux() *http.ServeMux {
	return s.mux
}

// StartAsync starts the server in a goroutine and returns any startup errors via channel
func (s *Server) StartAsync() error {
	errCh := make(chan error, 1)
	go func() {
		s.Setup()
		if err := s.Start(); err != nil && err != http.ErrServerClosed {
			errCh <- fmt.Errorf("server error: %w", err)
		}
		close(errCh)
	}()

	// Give the server a moment to start and check for immediate errors
	select {
	case err := <-errCh:
		return err
	default:
		return nil
	}
}
