package ntp

import (
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/fastdialer/fastdialer"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/extractors"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/generators"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/eventcreator"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/helpers/responsehighlighter"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/replacer"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/utils/vardump"
	protocolutils "github.com/projectdiscovery/nuclei/v3/pkg/protocols/utils"
	templateTypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/utils/json"
)

// defaultPort is the UDP port NTP servers listen on.
const defaultPort = "123"

// Request is a request for the NTP protocol
type Request struct {
	// Operators for the current request go here.
	operators.Operators `yaml:",inline,omitempty" json:",inline,omitempty"`
	CompiledOperators   *operators.Operators `yaml:"-" json:"-"`

	// ID is the optional id of the request
	ID string `yaml:"id,omitempty" json:"id,omitempty" jsonschema:"title=id of the request,description=ID of the ntp request"`

	// description: |
	//   Address contains the address for the request.
	//
	//   If not specified, the target input is used with the default NTP port 123.
	// examples:
	//   - value: "\"{{Host}}:{{Port}}\""
	Address string `yaml:"address,omitempty" json:"address,omitempty" jsonschema:"title=address for the NTP request,description=Address contains the address for the request"`

	options *protocols.ExecutorOptions
	dialer  *fastdialer.Dialer
}

// Compile compiles the request generators preparing any requests possible.
func (request *Request) Compile(options *protocols.ExecutorOptions) error {
	request.options = options
	if dialers := protocolstate.GetDialersWithId(options.Options.ExecutionId); dialers != nil {
		request.dialer = dialers.Fastdialer
	}

	if len(request.Matchers) > 0 || len(request.Extractors) > 0 {
		compiled := &request.Operators
		compiled.ExcludeMatchers = options.ExcludeMatchers
		compiled.TemplateID = options.TemplateID
		if err := compiled.Compile(); err != nil {
			return errors.Wrap(err, "could not compile operators")
		}
		protocols.BindLLMOperators(compiled, options)
		request.CompiledOperators = compiled
	}
	return nil
}

// Requests returns the total number of requests the rule will perform
func (request *Request) Requests() int {
	return 1
}

// GetID returns the ID for the request if any.
func (request *Request) GetID() string {
	return request.ID
}

// ExecuteWithResults executes the protocol requests and returns results instead of writing them.
func (request *Request) ExecuteWithResults(input *contextargs.Context, dynamicValues, previous output.InternalEvent, callback protocols.OutputEventCallback) error {
	// generate variables
	defaultVars := protocolutils.GenerateVariables(input.MetaInput.Input, false, nil)
	optionVars := generators.BuildPayloadFromOptions(request.options.Options)
	// add templatectx variables to varMap
	scope := request.options.NewVariablesScope(defaultVars, optionVars, dynamicValues, previous)

	request.options.AddTemplateCtxToVariablesScope(input.MetaInput, scope)
	scope.AddData(request.options.Constants)

	vars := request.options.Variables.EvaluateScope(scope).Values
	variables := generators.MergeMaps(vars, defaultVars, optionVars, dynamicValues, previous)
	if request.options.HasTemplateCtx(input.MetaInput) {
		variables = generators.MergeMaps(variables, request.options.GetTemplateCtx(input.MetaInput).GetAll())
	}
	variables = generators.MergeMaps(variables, request.options.Constants)

	if vardump.EnableVarDump {
		gologger.Debug().Msgf("NTP Protocol request variables: %s\n", vardump.DumpVariables(variables))
	}

	address := request.Address
	if address == "" {
		address = "{{Host}}:{{Port}}"
	}
	address = replacer.Replace(address, variables)
	host, port, err := splitHostPort(address)
	if err != nil {
		return errors.Wrap(err, "could not parse ntp address")
	}
	if port == "" {
		port = defaultPort
		address = fmt.Sprintf("%s:%s", host, port)
	}
	if !protocolstate.IsHostAllowed(request.options.Options.ExecutionId, host) {
		return errors.Errorf("ntp address %s is blocked by network policy", host)
	}

	if err := request.options.RateLimitTakeContext(input.Context(), address); err != nil {
		return errors.Wrap(err, "could not take rate limit")
	}

	response, requestDump, duration, err := request.exchange(input, address)
	if err != nil {
		return errors.Wrap(err, "could not make ntp request")
	}
	gologger.Verbose().Msgf("Sent NTP request to %s", address)
	if request.options.Options.Debug || request.options.Options.DebugRequests {
		gologger.Debug().Msgf("[%s] Dumped NTP request for %s:\n%s", request.options.TemplateID, address, hex.Dump(requestDump))
	}

	jsonData, _ := json.Marshal(response)
	jsonDataString := string(jsonData)

	data := make(map[string]interface{})
	data["type"] = request.Type().String()
	data["host"] = address
	data["request"] = hex.Dump(requestDump)
	data["response"] = jsonDataString
	data["version"] = response.Version
	data["stratum"] = response.Stratum
	data["refid"] = response.ReferenceID
	data["delay"] = response.Delay
	data["offset"] = response.Offset
	data["duration"] = duration.Seconds()

	// add response fields to template context and merge templatectx variables to output event
	request.options.AddTemplateVars(input.MetaInput, request.Type(), request.ID, data)
	data = generators.MergeMaps(data, request.options.GetTemplateCtx(input.MetaInput).GetAll())

	event := eventcreator.CreateEvent(request, data, request.options.Options.Debug || request.options.Options.DebugResponse)
	if request.options.Options.Debug || request.options.Options.DebugResponse {
		gologger.Debug().Msgf("[%s] Dumped NTP response for %s", request.options.TemplateID, address)
		gologger.Print().Msgf("%s", responsehighlighter.Highlight(event.OperatorsResult, jsonDataString, request.options.Options.NoColor, false))
	}

	callback(event)
	return nil
}

// exchange performs a single NTP query against the address and parses the
// response. It returns the parsed response, the raw request bytes and the
// round-trip duration.
func (request *Request) exchange(input *contextargs.Context, address string) (*Response, []byte, time.Duration, error) {
	dial := func() (conn net.Conn, err error) {
		if request.dialer != nil {
			return request.dialer.Dial(input.Context(), "udp", address)
		}
		var d net.Dialer
		return d.DialContext(input.Context(), "udp", address)
	}
	conn, err := dial()
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "could not connect to ntp server")
	}
	defer func() { _ = conn.Close() }()

	timeout := time.Duration(request.options.Options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	requestDump := marshalRequest(time.Now())
	timeStart := time.Now()
	if _, err := conn.Write(requestDump); err != nil {
		return nil, nil, 0, errors.Wrap(err, "could not send ntp request")
	}

	buffer := make([]byte, ntpPacketSize)
	n, err := conn.Read(buffer)
	receiveTime := time.Now()
	duration := time.Since(timeStart)
	if err != nil {
		return nil, nil, 0, errors.Wrap(err, "could not read ntp response")
	}

	response, err := parseResponse(buffer[:n], receiveTime)
	if err != nil {
		return nil, nil, 0, err
	}
	return response, requestDump, duration, nil
}

// splitHostPort splits an address into host and port, tolerating a missing
// port for both plain hosts and bracketed IPv6 hosts.
func splitHostPort(address string) (string, string, error) {
	if host, port, err := net.SplitHostPort(address); err == nil {
		return host, port, nil
	}
	if strings.Count(address, ":") == 0 || (strings.HasPrefix(address, "[") && strings.HasSuffix(address, "]")) {
		return strings.Trim(address, "[]"), "", nil
	}
	if strings.Count(address, ":") > 1 {
		// bare IPv6 host without port
		return address, "", nil
	}
	return "", "", errors.Errorf("invalid address: %s", address)
}

// Match performs matching operation for a matcher on model and returns:
// true and a list of matched snippets if the matcher type is supports it
// otherwise false and an empty string slice
func (request *Request) Match(data map[string]interface{}, matcher *matchers.Matcher) (bool, []string) {
	return protocols.MakeDefaultMatchFuncWithExecutorOptions(data, matcher, request.options)
}

// Extract performs extracting operation for an extractor on model and returns true or false.
func (request *Request) Extract(data map[string]interface{}, matcher *extractors.Extractor) map[string]struct{} {
	return protocols.MakeDefaultExtractFuncWithExecutorOptions(data, matcher, request.options)
}

// MakeResultEvent creates a result event from internal wrapped event
func (request *Request) MakeResultEvent(wrapped *output.InternalWrappedEvent) []*output.ResultEvent {
	return protocols.MakeDefaultResultEvent(request, wrapped)
}

// GetCompiledOperators returns a list of the compiled operators
func (request *Request) GetCompiledOperators() []*operators.Operators {
	return []*operators.Operators{request.CompiledOperators}
}

func (request *Request) MakeResultEventItem(wrapped *output.InternalWrappedEvent) *output.ResultEvent {
	data := &output.ResultEvent{
		TemplateID:       types.ToString(request.options.TemplateID),
		TemplatePath:     types.ToString(request.options.TemplatePath),
		Info:             request.options.TemplateInfo,
		TemplateVerifier: request.options.TemplateVerifier,
		Type:             types.ToString(wrapped.InternalEvent["type"]),
		Host:             types.ToString(wrapped.InternalEvent["host"]),
		Metadata:         wrapped.OperatorsResult.PayloadValues,
		ExtractedResults: wrapped.OperatorsResult.OutputExtracts,
		Timestamp:        time.Now(),
		MatcherStatus:    true,
		Request:          types.ToString(wrapped.InternalEvent["request"]),
		Response:         types.ToString(wrapped.InternalEvent["response"]),
		TemplateEncoded:  request.options.EncodeTemplate(),
		Error:            types.ToString(wrapped.InternalEvent["error"]),
	}
	return data
}

// RequestPartDefinitions contains a mapping of request part definitions and their
// description. Multiple definitions are separated by commas.
// Definitions not having a name (generated on runtime) are prefixed & suffixed by <>.
var RequestPartDefinitions = map[string]string{
	"type":     "Type is the type of request made",
	"host":     "Host is the input to the template",
	"request":  "NTP request dump",
	"response": "NTP server response data",
	"version":  "NTP protocol version reported by the server",
	"stratum":  "NTP server stratum",
	"refid":    "NTP server reference identifier",
	"delay":    "Round-trip network delay in seconds",
	"offset":   "Clock offset between server and client in seconds",
	"duration": "Protocol operation duration in seconds",
}

// Type returns the type of the protocol request
func (request *Request) Type() templateTypes.ProtocolType {
	return templateTypes.NTPProtocol
}

// UpdateOptions replaces this request's options with a new copy
func (request *Request) UpdateOptions(opts *protocols.ExecutorOptions) {
	request.Operators = protocols.CloneOperators(request.Operators)
	request.CompiledOperators = nil
	if request.options == nil {
		if opts != nil {
			request.options = opts.Copy()
		}
		return
	}
	request.options = request.options.Copy()
	request.options.ApplyNewEngineOptions(opts)
}
