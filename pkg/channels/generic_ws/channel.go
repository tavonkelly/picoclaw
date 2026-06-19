// Package generic_ws implements a generic WebSocket server channel.
//
// Unlike the Pico channel, generic_ws speaks a minimal JSON envelope with no
// protocol-specific fields. Clients connect to a single configurable path on
// the shared gateway HTTP server, optionally authenticate with a query-param
// token, and exchange `{content, session_id, sender_id}` JSON frames. It is
// intended as the lowest-friction way to bridge a custom front-end (browser,
// CLI, IoT device) to PicoClaw.
package generic_ws

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"github.com/sipeed/picoclaw/pkg/bus"
	"github.com/sipeed/picoclaw/pkg/channels"
	"github.com/sipeed/picoclaw/pkg/config"
	"github.com/sipeed/picoclaw/pkg/identity"
	"github.com/sipeed/picoclaw/pkg/logger"
)

const (
	channelName         = "generic_ws"
	defaultPath         = "/genericws/"
	defaultPingInterval = 30 * time.Second
	defaultReadTimeout  = 60 * time.Second
)

// wsConn tracks a single live WebSocket connection. The (sessionID, senderID)
// pair is mutable: each can be re-bound by a per-message field in any inbound
// frame, mirroring the connect-time query params.
type wsConn struct {
	id        string
	sessionID string
	senderID  string
	conn      *websocket.Conn
	writeMu   sync.Mutex
	closed    atomic.Bool
	cancel    context.CancelFunc
}

func (pc *wsConn) writeJSON(v any) error {
	if pc.closed.Load() {
		return fmt.Errorf("connection closed")
	}
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()
	return pc.conn.WriteJSON(v)
}

// effectiveSenderID returns the senderID the bus should see for a connection.
// If the client explicitly set one (via ?sender_id= or a per-message field),
// that wins. Otherwise we derive a stable value from sessionID so consecutive
// connections sharing a session_id map to the same canonical session key.
func effectiveSenderID(pc *wsConn) string {
	if pc.senderID != "" {
		return pc.senderID
	}
	return channelName + "-" + pc.sessionID
}

func (pc *wsConn) close() {
	if pc.closed.CompareAndSwap(false, true) {
		if pc.cancel != nil {
			pc.cancel()
		}
		_ = pc.conn.Close()
	}
}

type inboundFrame struct {
	Content   string `json:"content"`
	SessionID string `json:"session_id,omitempty"`
	SenderID  string `json:"sender_id,omitempty"`
}

type outboundFrame struct {
	Content   string `json:"content"`
	SessionID string `json:"session_id,omitempty"`
}

// Channel is a generic WebSocket server channel.
type Channel struct {
	*channels.BaseChannel
	bc        *config.Channel
	config    *config.GenericWSSettings
	path      string
	upgrader  websocket.Upgrader
	conns     map[string]*wsConn            // connID -> conn
	bySession map[string]map[string]*wsConn // sessionID -> connID -> conn
	mu        sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// NewChannel constructs a generic WebSocket channel.
func NewChannel(bc *config.Channel, cfg *config.GenericWSSettings, messageBus *bus.MessageBus) (*Channel, error) {
	base := channels.NewBaseChannel(channelName, cfg, messageBus, bc.AllowFrom)
	return &Channel{
		BaseChannel: base,
		bc:          bc,
		config:      cfg,
		path:        normalizePath(cfg.Path),
		upgrader: websocket.Upgrader{
			// Auth is enforced separately via ?token. Allow any origin so this
			// channel works for browser front-ends without per-origin config.
			CheckOrigin:     func(_ *http.Request) bool { return true },
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		conns:     make(map[string]*wsConn),
		bySession: make(map[string]map[string]*wsConn),
	}, nil
}

func normalizePath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return defaultPath
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if !strings.HasSuffix(p, "/") {
		p = p + "/"
	}
	return p
}

// Start implements channels.Channel.
func (c *Channel) Start(ctx context.Context) error {
	logger.InfoC(channelName, "Starting Generic WebSocket channel")
	c.ctx, c.cancel = context.WithCancel(ctx)
	c.SetRunning(true)
	logger.InfoCF(channelName, "Generic WebSocket channel started", map[string]any{
		"path": c.path,
	})
	return nil
}

// Stop implements channels.Channel.
func (c *Channel) Stop(ctx context.Context) error {
	logger.InfoC(channelName, "Stopping Generic WebSocket channel")
	c.SetRunning(false)
	for _, pc := range c.takeAll() {
		pc.close()
	}
	if c.cancel != nil {
		c.cancel()
	}
	logger.InfoC(channelName, "Generic WebSocket channel stopped")
	return nil
}

// WebhookPath implements channels.WebhookHandler — Manager will auto-register
// this on the shared gateway HTTP server.
func (c *Channel) WebhookPath() string { return c.path }

// ServeHTTP implements http.Handler — upgrades to a WebSocket connection.
func (c *Channel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !c.IsRunning() {
		http.Error(w, "channel not running", http.StatusServiceUnavailable)
		return
	}
	if !c.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := c.upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.ErrorCF(channelName, "WebSocket upgrade failed", map[string]any{
			"error": err.Error(),
		})
		return
	}

	sessionID := strings.TrimSpace(r.URL.Query().Get("session_id"))
	if sessionID == "" {
		sessionID = uuid.New().String()
	}
	// Leave senderID empty when the client did not pin one explicitly. The
	// effective senderID is derived from sessionID at dispatch time so that
	// it stays stable across reconnects sharing a session_id (PicoClaw's
	// session-key hash includes sender under dm_scope per-channel-peer/per-peer).
	senderID := strings.TrimSpace(r.URL.Query().Get("sender_id"))

	connCtx, connCancel := context.WithCancel(c.ctx)
	pc := &wsConn{
		id:        uuid.New().String(),
		conn:      conn,
		sessionID: sessionID,
		senderID:  senderID,
		cancel:    connCancel,
	}
	c.addConn(pc)

	logger.InfoCF(channelName, "WebSocket client connected", map[string]any{
		"conn_id":    pc.id,
		"session_id": sessionID,
		"sender_id":  effectiveSenderID(pc),
	})
	go c.readLoop(connCtx, pc)
}

// authenticate enforces the configured ?token query parameter. An empty
// Token means "open mode" (no auth) — useful for localhost / trusted networks.
func (c *Channel) authenticate(r *http.Request) bool {
	token := c.config.Token.String()
	if token == "" {
		return true
	}
	return r.URL.Query().Get("token") == token
}

func (c *Channel) addConn(pc *wsConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.conns[pc.id] = pc
	by, ok := c.bySession[pc.sessionID]
	if !ok {
		by = make(map[string]*wsConn)
		c.bySession[pc.sessionID] = by
	}
	by[pc.id] = pc
}

func (c *Channel) removeConn(id string) *wsConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	pc, ok := c.conns[id]
	if !ok {
		return nil
	}
	delete(c.conns, id)
	if by, ok := c.bySession[pc.sessionID]; ok {
		delete(by, id)
		if len(by) == 0 {
			delete(c.bySession, pc.sessionID)
		}
	}
	return pc
}

// rebindSession atomically moves the connection's bySession registration to
// newSessionID and updates pc.sessionID. Caller must not hold c.mu.
func (c *Channel) rebindSession(pc *wsConn, newSessionID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pc.sessionID == newSessionID {
		return
	}
	if by, ok := c.bySession[pc.sessionID]; ok {
		delete(by, pc.id)
		if len(by) == 0 {
			delete(c.bySession, pc.sessionID)
		}
	}
	pc.sessionID = newSessionID
	by, ok := c.bySession[newSessionID]
	if !ok {
		by = make(map[string]*wsConn)
		c.bySession[newSessionID] = by
	}
	by[pc.id] = pc
}

func (c *Channel) sessionSnapshot(sessionID string) []*wsConn {
	c.mu.RLock()
	defer c.mu.RUnlock()
	by, ok := c.bySession[sessionID]
	if !ok || len(by) == 0 {
		return nil
	}
	out := make([]*wsConn, 0, len(by))
	for _, pc := range by {
		out = append(out, pc)
	}
	return out
}

func (c *Channel) takeAll() []*wsConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]*wsConn, 0, len(c.conns))
	for _, pc := range c.conns {
		out = append(out, pc)
	}
	clear(c.conns)
	clear(c.bySession)
	return out
}

func (c *Channel) readLoop(connCtx context.Context, pc *wsConn) {
	defer func() {
		pc.close()
		if removed := c.removeConn(pc.id); removed != nil {
			logger.InfoCF(channelName, "WebSocket client disconnected", map[string]any{
				"conn_id":    removed.id,
				"session_id": removed.sessionID,
			})
		}
	}()

	readTimeout := time.Duration(c.config.ReadTimeout) * time.Second
	if readTimeout <= 0 {
		readTimeout = defaultReadTimeout
	}
	_ = pc.conn.SetReadDeadline(time.Now().Add(readTimeout))
	pc.conn.SetPongHandler(func(string) error {
		return pc.conn.SetReadDeadline(time.Now().Add(readTimeout))
	})

	pingInterval := time.Duration(c.config.PingInterval) * time.Second
	if pingInterval <= 0 {
		pingInterval = defaultPingInterval
	}
	go c.pingLoop(connCtx, pc, pingInterval)

	for {
		select {
		case <-connCtx.Done():
			return
		default:
		}

		_, raw, err := pc.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				logger.DebugCF(channelName, "WebSocket read error", map[string]any{
					"conn_id": pc.id,
					"error":   err.Error(),
				})
			}
			return
		}
		_ = pc.conn.SetReadDeadline(time.Now().Add(readTimeout))

		var frame inboundFrame
		if err := json.Unmarshal(raw, &frame); err != nil {
			logger.DebugCF(channelName, "Discarding malformed JSON frame", map[string]any{
				"conn_id": pc.id,
				"error":   err.Error(),
			})
			continue
		}
		c.dispatchInbound(pc, frame)
	}
}

func (c *Channel) pingLoop(connCtx context.Context, pc *wsConn, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-connCtx.Done():
			return
		case <-ticker.C:
			if pc.closed.Load() {
				return
			}
			pc.writeMu.Lock()
			err := pc.conn.WriteMessage(websocket.PingMessage, nil)
			pc.writeMu.Unlock()
			if err != nil {
				return
			}
		}
	}
}

func (c *Channel) dispatchInbound(pc *wsConn, frame inboundFrame) {
	if strings.TrimSpace(frame.Content) == "" {
		return
	}
	if frame.SessionID != "" && frame.SessionID != pc.sessionID {
		c.rebindSession(pc, frame.SessionID)
	}
	if frame.SenderID != "" && frame.SenderID != pc.senderID {
		pc.senderID = frame.SenderID
	}

	sessionID := pc.sessionID
	senderID := effectiveSenderID(pc)
	sender := bus.SenderInfo{
		Platform:    channelName,
		PlatformID:  senderID,
		CanonicalID: identity.BuildCanonicalID(channelName, senderID),
	}
	chatID := channelName + ":" + sessionID
	inboundCtx := bus.InboundContext{
		Channel:  c.Name(),
		ChatID:   chatID,
		ChatType: "direct",
		SenderID: senderID,
		Raw: map[string]string{
			"platform":   channelName,
			"session_id": sessionID,
			"sender_id":  senderID,
		},
	}
	c.HandleInboundContext(c.ctx, chatID, frame.Content, nil, inboundCtx, sender)
}

// Send broadcasts an agent reply to every connection currently bound to the
// session identified by msg.ChatID. Returns (nil, firstErr) — outbound frames
// are not assigned message IDs.
func (c *Channel) Send(ctx context.Context, msg bus.OutboundMessage) ([]string, error) {
	if !c.IsRunning() {
		return nil, channels.ErrNotRunning
	}
	if strings.TrimSpace(msg.Content) == "" {
		return nil, nil
	}
	sessionID := strings.TrimPrefix(msg.ChatID, channelName+":")
	conns := c.sessionSnapshot(sessionID)
	if len(conns) == 0 {
		return nil, nil
	}
	out := outboundFrame{Content: msg.Content, SessionID: sessionID}
	var firstErr error
	for _, pc := range conns {
		if err := pc.writeJSON(out); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return nil, firstErr
}
