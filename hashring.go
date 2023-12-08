package pushproxy

import (
	"fmt"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/reverseproxy"
	"github.com/zeromicro/go-zero/core/hash"
)

type ConsistentHansh struct {
	ring *hash.ConsistentHash
}

func newConsistentHash(pool []*reverseproxy.Upstream) *ConsistentHansh {
	// minReplicas=100 虚拟节点
	cons := hash.NewConsistentHash()
	for _, item := range pool {
		cons.Add(item.Dial)
	}
	return &ConsistentHansh{
		ring: cons,
	}
}

// 自动检测并删除节点
func (c *ConsistentHansh) GetNode(labels map[string]string) (string, error) {
	node, ok := c.ring.Get(labels)
	if ok {
		return node.(string), nil
	} else {
		return "", fmt.Errorf("no node find in ring.")
	}
}
