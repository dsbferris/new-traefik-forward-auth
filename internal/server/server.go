package server

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/dsbferris/new-traefik-forward-auth/appconfig"
	"github.com/dsbferris/new-traefik-forward-auth/auth"
)

// Server contains router and handler methods
type Server struct {
	config *appconfig.AppConfig
	auth   *auth.Auth
	logger *slog.Logger
	router *http.ServeMux
	server *http.Server
}

// NewServer creates a new server object and builds router
func NewServer(logger *slog.Logger, config *appconfig.AppConfig) *Server {

	// parse port into correct format
	port := fmt.Sprintf(":%d", config.Port)
	// create new Server struct
	s := &Server{
		config: config,
		auth:   auth.NewAuth(config),
		logger: logger,
		router: http.NewServeMux(),
		server: &http.Server{
			Addr: port,
		},
	}
	// add routes
	s.addRoutes()

	// create our middleware chain
	middlewares := Chain(
		s.Logging,
		RewriteRequest,
		//s.Logging,
	)
	// set our middlewares followed by the definied routes
	s.server.Handler = middlewares(s.router)
	return s
}

func (s *Server) Start() {
	s.logger.Debug("Starting with config", slog.String("config", s.config.String()))
	s.logger.Info("Listening on ", slog.Int("port", s.config.Port))

	// Attach router to default server
	//http.HandleFunc("/", s.RootHandler)
	err := s.server.ListenAndServe()
	s.logger.Info("Terminated", slog.String("error", err.Error()))
}

func (s *Server) addRoutes() {
	// Add callback handler
	s.router.HandleFunc(s.config.UrlPath, s.AuthCallbackHandler)
	// Add login / logout handler
	s.router.HandleFunc(s.config.UrlPath+"/login", s.LoginHandler)
	s.router.HandleFunc(s.config.UrlPath+"/logout", s.LogoutHandler)
	// Add health check handler
	s.router.Handle("/health", http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	}))
	// Add a default handler
	s.router.HandleFunc("/", s.authHandler)
}
