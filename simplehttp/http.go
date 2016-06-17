package simplehttp

import (
	"io/ioutil"
	"log"
	"net/http"
)

// HandleFunc will handle requests.
// Returning a status code will return an HTTP <status> to the user
// with the corresponding error message.
// Returning an error will result in an HTTP 500: internal server error
// and the error being logged.
// Writing to the httpResponseWriter is mutually exclusive with returning anything
// other than 0, nil
type HandleFunc func(w http.ResponseWriter, r *http.Request, l *log.Logger) (errStatus int, err error)

// Router decides which handleFunc should handle the given http.Request.
// Returning no handler: 404.
// Returning an errorStatus: HTTP <errorStatus>.
type Router func(r *http.Request, l *log.Logger) (handler HandleFunc, errStatus int)

// HTTPErrorHandler can write to an http.ResponseWriter
type HTTPErrorHandler interface {
	WriteTo(w http.ResponseWriter)
	GetHeaders() map[string]string
}

// HTTPError is a static HTTPErrorHandler implementation
type HTTPError struct {
	headers map[string]string
	content []byte
}

// GetHeaders returns the headers
func (h *HTTPError) GetHeaders() map[string]string {
	return h.headers
}

// WriteTo the given http.ResponseWriter
func (h *HTTPError) WriteTo(w http.ResponseWriter) {
	w.Write(h.content)
}

// NewHTTPError returns an HTTPError instance
func NewHTTPError(contentType string, content []byte) *HTTPError {
	return &HTTPError{map[string]string{"Content-Type": contentType}, content}
}

// Server is a tiny wrapper around an http.Server{}
type Server struct {
	s          *http.Server
	log        *log.Logger
	router     Router
	httpErrors map[int]HTTPErrorHandler
	headers    map[string]string
}

// New returns a new Server with the given router.
func New(router Router, logger *log.Logger) *Server {
	return FromHTTPServer(&http.Server{}, router, logger)
}

// FromHTTPServer converts an http.Server into a Server using the given router.
func FromHTTPServer(
	server *http.Server,
	router Router,
	logger *log.Logger,
) *Server {
	mux := http.NewServeMux()
	if logger == nil {
		logger = log.New(ioutil.Discard, "", 0)
	}

	s := &Server{
		router:     router,
		log:        logger,
		httpErrors: make(map[int]HTTPErrorHandler),
		headers:    make(map[string]string),
	}

	mux.HandleFunc("/", s.reqHandler)
	s.s = server
	s.s.Handler = mux
	if s.s.ErrorLog == nil {
		s.s.ErrorLog = logger
	}

	return s
}

// SetHeader adds a header to all future reponses.
// Not thread safe.
func (s *Server) SetHeader(name string, value string) {
	s.headers[name] = value
}

// RemoveHeader removes a header from all future reponses.
// Not thread safe.
func (s *Server) RemoveHeader(name string) {
	delete(s.headers, name)
}

// Start listening on the given address
func (s *Server) Start(addr string, tls bool) error {
	s.s.Addr = addr
	if tls {
		return s.s.ListenAndServeTLS("", "")
	}

	return s.s.ListenAndServe()
}

// SetHTTPErrorHandler adds or overrides an http error handler.
// Not thread safe.
func (s *Server) SetHTTPErrorHandler(status int, handler HTTPErrorHandler) {
	s.httpErrors[status] = handler
}

func (s *Server) reqHandler(w http.ResponseWriter, r *http.Request) {
	handler, status := s.router(r, s.log)
	if status != 0 {
		s.serveError(w, status, nil)
		return
	}

	if handler == nil {
		s.serveError(w, http.StatusNotFound, nil)
		return
	}

	s.handleRequest(w, r, handler)
}

func (s *Server) handleRequest(w http.ResponseWriter, r *http.Request, cb HandleFunc) {
	gz := &gzipWriter{ResponseWriter: w, r: r}
	defer gz.Close()
	w = gz

	headers := w.Header()
	for name, value := range s.headers {
		headers.Set(name, value)
	}

	status, err := cb(w, r, s.log)
	if status != 0 {
		s.serveError(w, status, err)
		return
	}

	if err != nil {
		s.serveError(w, http.StatusInternalServerError, err)
	}
}

func (s *Server) serveError(w http.ResponseWriter, which int, err error) {
	if err != nil {
		s.log.Printf("%v", err)
	}

	headers := w.Header()
	headers.Set("Content-Type", "text/plain")

	if v, ok := s.httpErrors[which]; ok {
		for key, value := range v.GetHeaders() {
			headers.Set(key, value)
		}

		w.WriteHeader(which)
		v.WriteTo(w)
		return
	}

	if v := http.StatusText(which); v != "" {
		w.WriteHeader(which)
		w.Write([]byte(v))
		return
	}

	w.WriteHeader(http.StatusInternalServerError)
}
