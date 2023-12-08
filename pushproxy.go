package pushproxy

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/prometheus/common/model"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(PushgatewaySelection{})
}

// PushgatewaySelection is an example; put your own type here.
type PushgatewaySelection struct {
	// pushgateway prefix
	Prefix string `json:"prefix,omitempty"`
	hash   *ConsistentHansh
	logger *zap.Logger
	lock   *sync.RWMutex
}

// CaddyModule returns the Caddy module information.
func (PushgatewaySelection) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.reverse_proxy.selection_policies.pushproxy",
		New: func() caddy.Module { return new(PushgatewaySelection) },
	}
}

func (r *PushgatewaySelection) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		args := d.RemainingArgs()
		switch len(args) {
		case 0:
			r.Prefix = "/metrics"
		case 1:
			r.Prefix = args[0]
		default:
			return d.ArgErr()
		}
	}
	return nil
}

// Validate ensures that r's configuration is valid.
func (r PushgatewaySelection) Validate() error {
	return nil
}

func (u *PushgatewaySelection) Provision(ctx caddy.Context) error {
	u.logger = ctx.Logger()
	u.lock = &sync.RWMutex{}
	return nil
}

func (u *PushgatewaySelection) Select(pool reverseproxy.UpstreamPool, r *http.Request, w http.ResponseWriter) *reverseproxy.Upstream {
	if u.hash == nil {
		u.lock.Lock()
		u.hash = newConsistentHash(pool)
		u.lock.Unlock()
	}

	labels, err := u.splitLabels(r.RequestURI)
	if err != nil {
		u.logger.Error("pushproxy", zap.Error(err))
		w.Write([]byte(err.Error()))
		return nil
	}
	up, err := u.hash.GetNode(labels)
	if err != nil {
		u.logger.Error("pushproxy", zap.Error(err))
		w.Write([]byte(err.Error()))
		return nil
	}
	u.logger.Info("pushproxy", zap.String("upstream", up), zap.Any("uri", labels))
	for _, item := range pool {
		if item.Dial == up {
			return item
		}
	}
	return nil
}

const (
	Base64Suffix = "@base64"
)

func decodeBase64(s string) (string, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	return string(b), err
}

func (u *PushgatewaySelection) splitLabels(uri string) (map[string]string, error) {
	labels := strings.TrimLeft(uri, u.Prefix)
	result := map[string]string{}
	if len(labels) <= 1 {
		return result, nil
	}
	components := strings.Split(labels, "/")
	if len(components)%2 != 0 {
		return nil, fmt.Errorf("odd number of components in label string %q", labels)
	}

	for i := 0; i < len(components)-1; i += 2 {
		name, value := components[i], components[i+1]
		trimmedName := strings.TrimSuffix(name, Base64Suffix)
		if !model.LabelNameRE.MatchString(trimmedName) ||
			strings.HasPrefix(trimmedName, model.ReservedLabelPrefix) {
			return nil, fmt.Errorf("improper label name %q", trimmedName)
		}
		if name == trimmedName {
			result[name] = value
			continue
		}
		decodedValue, err := decodeBase64(value)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 encoding for label %s=%q: %v", trimmedName, value, err)
		}
		result[trimmedName] = decodedValue
	}
	return result, nil
}

// Interface guards
var (
	_ caddy.Provisioner     = (*PushgatewaySelection)(nil)
	_ caddy.Validator       = (*PushgatewaySelection)(nil)
	_ caddyfile.Unmarshaler = (*PushgatewaySelection)(nil)
	_ reverseproxy.Selector = (*PushgatewaySelection)(nil)
)
