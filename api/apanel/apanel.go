package apanel

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/go-resty/resty/v2"
)

type APIClient struct {
	client        *resty.Client
	APIHost       string
	NodeID        int
	Key           string
	NodeType      string
	EnableVless   bool
	EnableXTLS    bool
	SpeedLimit    float64
	DeviceLimit   int
	LocalRuleList []api.DetectRule
}

func New(apiConfig *api.Config) *APIClient {

	client := resty.New()
	client.SetRetryCount(3)
	if apiConfig.Timeout > 0 {
		client.SetTimeout(time.Duration(apiConfig.Timeout) * time.Second)
	} else {
		client.SetTimeout(5 * time.Second)
	}
	client.OnError(func(req *resty.Request, err error) {
		if v, ok := err.(*resty.ResponseError); ok {
			// v.Response contains the last response from the server
			// v.Err contains the original error
			log.Print(v.Err)
		}
	})
	client.SetBaseURL(apiConfig.APIHost)

	// Read local rule list
	localRuleList := readLocalRuleList(apiConfig.RuleListPath)
	apiClient := &APIClient{
		client:        client,
		NodeID:        apiConfig.NodeID,
		Key:           apiConfig.Key,
		APIHost:       apiConfig.APIHost,
		NodeType:      apiConfig.NodeType,
		EnableVless:   apiConfig.EnableVless,
		EnableXTLS:    apiConfig.EnableXTLS,
		SpeedLimit:    apiConfig.SpeedLimit,
		DeviceLimit:   apiConfig.DeviceLimit,
		LocalRuleList: localRuleList,
	}
	apiClient.client.SetDebug(true)
	return apiClient
}

// readLocalRuleList reads the local rule list file
func readLocalRuleList(path string) (LocalRuleList []api.DetectRule) {

	LocalRuleList = make([]api.DetectRule, 0)
	if path != "" {
		// open the file
		file, err := os.Open(path)

		// handle errors while opening
		if err != nil {
			log.Printf("Error when opening file: %s", err)
			return LocalRuleList
		}

		fileScanner := bufio.NewScanner(file)

		// read line by line
		for fileScanner.Scan() {
			LocalRuleList = append(LocalRuleList, api.DetectRule{
				ID:      -1,
				Pattern: regexp.MustCompile(fileScanner.Text()),
			})
		}
		// handle first encountered error while reading
		if err := fileScanner.Err(); err != nil {
			log.Fatalf("Error while reading file: %s", err)
			return
		}

		file.Close()
	}

	return LocalRuleList
}

// Describe return a description of the client
func (c *APIClient) Describe() api.ClientInfo {
	return api.ClientInfo{APIHost: c.APIHost, NodeID: c.NodeID, Key: c.Key, NodeType: c.NodeType}
}

// Debug set the client debug for client
func (c *APIClient) Debug() {
	c.client.SetDebug(true)
}

func (c *APIClient) assembleURL(path string) string {
	return c.APIHost + path
}

func (c *APIClient) createCommonRequest() *resty.Request {
	request := c.client.R().EnableTrace()
	request.EnableTrace()
	request.SetHeader("key", c.Key)
	request.SetHeader("timestamp", strconv.FormatInt(time.Now().Unix(), 10))
	return request
}

func (c *APIClient) parseResponse(res *resty.Response, path string, err error) (*Response, error) {
	if err != nil {
		return nil, fmt.Errorf("request %s failed: %s", c.assembleURL(path), err)
	}

	if res.StatusCode() > 400 {
		body := res.Body()
		return nil, fmt.Errorf("request %s failed: %s, %s", c.assembleURL(path), string(body), err)
	}
	response := res.Result().(*Response)

	if response.Status != "success" {
		res, _ := json.Marshal(&response)
		return nil, fmt.Errorf("ret %s invalid", string(res))
	}
	return response, nil
}

// GetNodeInfo will pull NodeInfo Config from sspanel
func (c *APIClient) GetNodeInfo() (nodeInfo *api.NodeInfo, err error) {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = fmt.Sprintf("/api/v2ray/%d", c.NodeID)
	case "Trojan":
		path = fmt.Sprintf("/api/trojan/%d", c.NodeID)
	case "Shadowsocks":
		path = fmt.Sprintf("/api/ss/%d", c.NodeID)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	res, err := c.createCommonRequest().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	if c.NodeType == "V2ray" || c.NodeType == "Trojan" || c.NodeType == "Shadowsocks" {
		nodeInfo, err = c.ParseNodeResponse(&response.Data)
	} else {
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := json.Marshal(response.Data)
		return nil, fmt.Errorf("Parse node info failed: %s, \nError: %s", string(res), err)
	}

	return nodeInfo, nil
}

// GetUserList will pull user form sapanel
func (c *APIClient) GetUserList() (UserList *[]api.UserInfo, err error) {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = fmt.Sprintf("/api/v2ray/%d/users", c.NodeID)
	case "Trojan":
		path = fmt.Sprintf("/api/trojan/%d/users", c.NodeID)
	case "Shadowsocks":
		path = fmt.Sprintf("/api/ss/%d/users", c.NodeID)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	res, err := c.createCommonRequest().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}
	userList := new([]api.UserInfo)
	if c.NodeType == "V2ray" || c.NodeType == "Trojan" || c.NodeType == "Shadowsocks" {
		userList, err = c.ParseUserListResponse(&response.Data)
	} else {
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	if err != nil {
		res, _ := json.Marshal(response.Data)
		return nil, fmt.Errorf("parse user list failed: %s", string(res))
	}
	return userList, nil
}

// ReportNodeStatus reports the node status to the sapanel
func (c *APIClient) ReportNodeStatus(nodeStatus *api.NodeStatus) (err error) {
	var path = fmt.Sprintf("/api/status/%d", c.NodeID)

	systemLoad := NodeStatus{
		Uptime: int(nodeStatus.Uptime),
		CPU:    fmt.Sprintf("%d%%", int(nodeStatus.CPU)),
		Mem:    fmt.Sprintf("%d%%", int(nodeStatus.Mem)),
		Disk:   fmt.Sprintf("%d%%", int(nodeStatus.Disk)),
	}

	res, err := c.createCommonRequest().
		SetBody(systemLoad).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportNodeOnlineUsers reports online user ip
func (c *APIClient) ReportNodeOnlineUsers(onlineUserList *[]api.OnlineUser) error {

	var path = fmt.Sprintf("/api/online-users/%d", c.NodeID)

	data := make([]NodeOnline, len(*onlineUserList))
	for i, user := range *onlineUserList {
		data[i] = NodeOnline{UID: user.UID, IP: user.IP}
	}

	res, err := c.createCommonRequest().
		SetBody(data).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// ReportUserTraffic reports the user traffic
func (c *APIClient) ReportUserTraffic(userTraffic *[]api.UserTraffic) error {
	var path = fmt.Sprintf("/api/node-usage/%d", c.NodeID)

	data := make([]UserTraffic, len(*userTraffic))
	for i, traffic := range *userTraffic {
		data[i] = UserTraffic{
			UID:      traffic.UID,
			Upload:   traffic.Upload,
			Download: traffic.Download,
			Email:    traffic.Email,
		}
	}
	res, err := c.createCommonRequest().
		SetBody(data).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(path)

	_, err = c.parseResponse(res, path, err)
	if err != nil {
		return err
	}

	return nil
}

// GetNodeRule will pull the audit rule form sapanel
func (c *APIClient) GetNodeRule() (*[]api.DetectRule, error) {
	var path string
	switch c.NodeType {
	case "V2ray":
		path = fmt.Sprintf("/api/v2ray/%d/rules", c.NodeID)
	case "Trojan":
		path = fmt.Sprintf("/api/trojan/%d/rules", c.NodeID)
	case "Shadowsocks":
		path = fmt.Sprintf("/api/ss/%d/rules", c.NodeID)
	default:
		return nil, fmt.Errorf("unsupported Node type: %s", c.NodeType)
	}

	res, err := c.createCommonRequest().
		SetResult(&Response{}).
		ForceContentType("application/json").
		Get(path)

	response, err := c.parseResponse(res, path, err)
	if err != nil {
		return nil, err
	}

	ruleListResponse := new(NodeRule)

	if err := json.Unmarshal(response.Data, ruleListResponse); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(ruleListResponse), err)
	}
	ruleList := c.LocalRuleList
	// Only support reject rule type
	if ruleListResponse.Mode != "reject" {
		return &ruleList, nil
	} else {
		for _, r := range ruleListResponse.Rules {
			if r.Type == "reg" {
				ruleList = append(ruleList, api.DetectRule{
					ID:      r.ID,
					Pattern: regexp.MustCompile(r.Pattern),
				})
			}

		}
	}

	return &ruleList, nil
}

// ReportIllegal reports the user illegal behaviors
func (c *APIClient) ReportIllegal(detectResultList *[]api.DetectResult) error {
	var path = fmt.Sprintf("/api/illegal/%d", c.NodeID)

	for _, r := range *detectResultList {
		res, err := c.createCommonRequest().
			SetBody(IllegalReport{
				RuleID: r.RuleID,
				UID:    r.UID,
			}).
			SetResult(&Response{}).
			ForceContentType("application/json").
			Post(path)

		_, err = c.parseResponse(res, path, err)
		if err != nil {
			return err
		}
	}

	return nil
}

func (c *APIClient) ParseNodeResponse(nodeInfoResponse *json.RawMessage) (*api.NodeInfo, error) {
	var TLStype string
	var speedLimit uint64 = 0
	if c.EnableXTLS {
		TLStype = "xtls"
	} else {
		TLStype = "tls"
	}

	nodeInfo := new(NodeInfo)
	if err := json.Unmarshal(*nodeInfoResponse, nodeInfo); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(*nodeInfoResponse), err)
	}

	if c.SpeedLimit > 0 {
		speedLimit = uint64((c.SpeedLimit * 1000000) / 8)
	} else {
		speedLimit = uint64((nodeInfo.SpeedLimit * 1000000) / 8)
	}

	if c.DeviceLimit == 0 && nodeInfo.DeviceLimit > 0 {
		c.DeviceLimit = nodeInfo.DeviceLimit
	}

	// Create GeneralNodeInfo
	nodeinfo := &api.NodeInfo{
		NodeType:          c.NodeType,
		NodeID:            c.NodeID,
		Port:              nodeInfo.Port,
		SpeedLimit:        speedLimit,
		AlterID:           nodeInfo.AlterID,
		TransportProtocol: nodeInfo.TransportProtocol,
		FakeType:          nodeInfo.FakeType,
		EnableTLS:         nodeInfo.EnableTLS,
		TLSType:           TLStype,
		Path:              nodeInfo.Path,
		Host:              nodeInfo.Host,
		EnableVless:       c.EnableVless,
		CypherMethod:      nodeInfo.CypherMethod,
		ServerKey:         nodeInfo.ServerKey,
		ServiceName:       nodeInfo.ServiceName,
		Header:            nodeInfo.Header,
	}

	return nodeinfo, nil
}

// ParseV2rayUserListResponse parse the response for the given userinfo format
func (c *APIClient) ParseUserListResponse(userInfoResponse *json.RawMessage) (*[]api.UserInfo, error) {
	var speedLimit uint64 = 0

	nodeUserList := new([]*UserInfo)
	if err := json.Unmarshal(*userInfoResponse, nodeUserList); err != nil {
		return nil, fmt.Errorf("unmarshal %s failed: %s", reflect.TypeOf(*userInfoResponse), err)
	}

	userList := make([]api.UserInfo, len(*nodeUserList))
	for i, user := range *nodeUserList {
		userList[i] = api.UserInfo{
			UID:           user.UID,
			Email:         user.Email,
			UUID:          user.UUID,
			DeviceLimit:   user.DeviceLimit,
			SpeedLimit:    speedLimit,
			Passwd:        user.Passwd,
			Port:          user.Port,
			Method:        user.Method,
			Protocol:      user.Protocol,
			ProtocolParam: user.ProtocolParam,
			Obfs:          user.Obfs,
			ObfsParam:     user.ObfsParam,
			AlterID:       user.AlterID,
		}
	}

	return &userList, nil
}
