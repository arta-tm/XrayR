package apanel

import (
	"encoding/json"
)

type Response struct {
	Status  string          `json:"status"`
	Code    int             `json:"code"`
	Data    json.RawMessage `json:"data"`
	Message string          `json:"message"`
}

type NodeInfo struct {
	NodeType          string          `json:"type"` // Must be V2ray, Trojan, and Shadowsocks
	NodeID            int             `json:"id"`
	Port              uint32          `json:"port"`
	SpeedLimit        uint64          `json:"speedLimit"` // Bps
	DeviceLimit       int             `json:"deviceLimit"`
	AlterID           uint16          `json:"alterId"`
	TransportProtocol string          `json:"transportProtocol"`
	FakeType          string          `json:"fakeType"`
	Host              string          `json:"url"`
	Path              string          `json:"path"`
	EnableTLS         bool            `json:"enableTLS"`
	TLSType           string          `json:"tlsType"`
	EnableVless       bool            `json:"enableVless"`
	CypherMethod      string          `json:"cypherMethod"`
	ServerKey         string          `json:"serverKey"`
	ServiceName       string          `json:"serviceName"`
	Header            json.RawMessage `json:"header"`

	// NameServerConfig  []*conf.NameServerConfig `json:"name_server_config"`
}

type UserInfo struct {
	UID           int    `json:"id"`
	Email         string `json:"email"`
	Passwd        string `json:"password"`
	Port          uint32 `json:"port"`
	Method        string `json:"method"`
	SpeedLimit    uint64 `json:"speedLimit"` // Bps
	DeviceLimit   int    `json:"deviceLimit"`
	Protocol      string `json:"protocol"`
	ProtocolParam string `json:"protocolParam"`
	Obfs          string `json:"obfs"`
	ObfsParam     string `json:"obfsParam"`
	UUID          string `json:"uuid"`
	AlterID       uint16 `json:"alterId"`
}

type NodeStatus struct {
	CPU    string `json:"cpu"`
	Mem    string `json:"mem"`
	Net    string `json:"net"`
	Disk   string `json:"disk"`
	Uptime int    `json:"uptime"`
}

type NodeOnline struct {
	UID int    `json:"uid"`
	IP  string `json:"ip"`
}

type UserTraffic struct {
	UID      int    `json:"uid"`
	Upload   int64  `json:"upload"`
	Download int64  `json:"download"`
	Email    string `json:"email"`
}

type NodeRule struct {
	Mode  string         `json:"mode"`
	Rules []NodeRuleItem `json:"rules"`
}

type NodeRuleItem struct {
	ID      int    `json:"id"`
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
}

type IllegalReport struct {
	UID    int `json:"uid"`
	RuleID int `json:"rule_id"`
}
