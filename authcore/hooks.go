package authcore

// HookManager defines the interface for hooks triggered during authentication events
type HookManager interface {
	// OnLoginSuccess is called when a user successfully logs in
	OnLoginSuccess(userID string, claims map[string]interface{})
	// OnTokenRefresh is called when a token is refreshed
	OnTokenRefresh(oldToken, newToken *RefreshToken)
	// OnTokenRevoked is called when a token is revoked
	OnTokenRevoked(token *RefreshToken)
	// OnAuthenticationFailed is called when authentication fails
	OnAuthenticationFailed(err error)
}

// DefaultHookManager is a no-op implementation of HookManager
type DefaultHookManager struct {
	config Config
}

// NewDefaultHookManager creates a new DefaultHookManager
func NewDefaultHookManager(config Config) *DefaultHookManager {
	return &DefaultHookManager{
		config: config,
	}
}

// OnLoginSuccess is called when a user successfully logs in
func (h *DefaultHookManager) OnLoginSuccess(userID string, claims map[string]interface{}) {
	// Log the event
	if h.config.Logger != nil {
		h.config.Logger.Info("login success",
			"user_id", userID,
		)
	}
}

// OnTokenRefresh is called when a token is refreshed
func (h *DefaultHookManager) OnTokenRefresh(oldToken, newToken *RefreshToken) {
	// Log the event
	if h.config.Logger != nil {
		h.config.Logger.Info("token refreshed",
			"user_id", oldToken.UserID,
			"old_token_id", oldToken.ID,
			"new_token_id", newToken.ID,
		)
	}
}

// OnTokenRevoked is called when a token is revoked
func (h *DefaultHookManager) OnTokenRevoked(token *RefreshToken) {
	// Log the event
	if h.config.Logger != nil {
		h.config.Logger.Info("token revoked",
			"user_id", token.UserID,
			"token_id", token.ID,
		)
	}
}

// OnAuthenticationFailed is called when authentication fails
func (h *DefaultHookManager) OnAuthenticationFailed(err error) {
	// Log the event
	if h.config.Logger != nil {
		h.config.Logger.Warn("authentication failed",
			"error", err.Error(),
		)
	}
}

// CompositeHookManager allows multiple hook implementations to be used
type CompositeHookManager struct {
	hooks []HookManager
}

// NewCompositeHookManager creates a new CompositeHookManager
func NewCompositeHookManager(hooks ...HookManager) *CompositeHookManager {
	return &CompositeHookManager{
		hooks: hooks,
	}
}

// OnLoginSuccess is called when a user successfully logs in
func (h *CompositeHookManager) OnLoginSuccess(userID string, claims map[string]interface{}) {
	for _, hook := range h.hooks {
		hook.OnLoginSuccess(userID, claims)
	}
}

// OnTokenRefresh is called when a token is refreshed
func (h *CompositeHookManager) OnTokenRefresh(oldToken, newToken *RefreshToken) {
	for _, hook := range h.hooks {
		hook.OnTokenRefresh(oldToken, newToken)
	}
}

// OnTokenRevoked is called when a token is revoked
func (h *CompositeHookManager) OnTokenRevoked(token *RefreshToken) {
	for _, hook := range h.hooks {
		hook.OnTokenRevoked(token)
	}
}

// OnAuthenticationFailed is called when authentication fails
func (h *CompositeHookManager) OnAuthenticationFailed(err error) {
	for _, hook := range h.hooks {
		hook.OnAuthenticationFailed(err)
	}
}

// AddHook adds a hook to the manager
func (h *CompositeHookManager) AddHook(hook HookManager) {
	h.hooks = append(h.hooks, hook)
}

// MetricsHook implements HookManager for metrics collection
type MetricsHook struct {
	// Metrics placeholders for future implementation
	// loginCounter      prometheus.Counter
	// refreshCounter    prometheus.Counter
	// revokeCounter     prometheus.Counter
	// failureCounter    prometheus.Counter
}

// NewMetricsHook creates a new MetricsHook
func NewMetricsHook() *MetricsHook {
	// In a future implementation, this would initialize Prometheus metrics
	return &MetricsHook{}
}

// OnLoginSuccess is called when a user successfully logs in
func (h *MetricsHook) OnLoginSuccess(userID string, claims map[string]interface{}) {
	// Increment metrics (future implementation)
	// h.loginCounter.Inc()
}

// OnTokenRefresh is called when a token is refreshed
func (h *MetricsHook) OnTokenRefresh(oldToken, newToken *RefreshToken) {
	// Increment metrics (future implementation)
	// h.refreshCounter.Inc()
}

// OnTokenRevoked is called when a token is revoked
func (h *MetricsHook) OnTokenRevoked(token *RefreshToken) {
	// Increment metrics (future implementation)
	// h.revokeCounter.Inc()
}

// OnAuthenticationFailed is called when authentication fails
func (h *MetricsHook) OnAuthenticationFailed(err error) {
	// Increment metrics (future implementation)
	// h.failureCounter.Inc()
}
