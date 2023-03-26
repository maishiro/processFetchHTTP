//go:generate ../../../tools/readme_config_includer/generator
package http

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"strings"
	"sync"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/models"
	"github.com/influxdata/toml"
	"github.com/influxdata/toml/ast"

	httpconfig "github.com/influxdata/telegraf/plugins/common/http"
	"github.com/influxdata/telegraf/plugins/parsers"
	"github.com/influxdata/telegraf/plugins/parsers/csv"
	_ "github.com/influxdata/telegraf/plugins/parsers/xpath"
	"github.com/influxdata/telegraf/plugins/processors"
	"github.com/influxdata/telegraf/plugins/serializers"
)

var (
	// envVarRe is a regex to find environment variables in the config file
	envVarRe = regexp.MustCompile(`\${(\w+)}|\$(\w+)`)

	envVarEscaper = strings.NewReplacer(
		`"`, `\"`,
		`\`, `\\`,
	)
	// httpLoadConfigRetryInterval = 10 * time.Second

	// // fetchURLRe is a regex to determine whether the requested file should
	// // be fetched from a remote or read from the filesystem.
	// fetchURLRe = regexp.MustCompile(`^\w+://`)

	// // Password specified via command-line
	// Password Secret
)

//go:embed sample.conf
var sampleConfig string

type HTTP struct {
	URLs            []string `toml:"urls"`
	Method          string   `toml:"method"`
	Body            string   `toml:"body"`
	ContentEncoding string   `toml:"content_encoding"`

	Headers map[string]string `toml:"headers"`

	// HTTP Basic Auth Credentials
	Username config.Secret `toml:"username"`
	Password config.Secret `toml:"password"`

	// Absolute path to file with Bearer token
	BearerToken string `toml:"bearer_token"`

	SuccessStatusCodes []int `toml:"success_status_codes"`

	DataFormat string `toml:"data_format"`

	Log telegraf.Logger `toml:"-"`

	UnusedFields map[string]bool
	unusedFieldsMutex *sync.Mutex
	Toml         *toml.Config
	errs         []error // config load errors.

	httpconfig.HTTPClientConfig
	serializerConfig *serializers.Config
	serializer       serializers.Serializer

	client     *http.Client
	parser           telegraf.Parser
	parserFunc telegraf.ParserFunc
}

func (*HTTP) SampleConfig() string {
	return sampleConfig
}

func (h *HTTP) Init() error {
	h.UnusedFields = map[string]bool{}
	h.unusedFieldsMutex = &sync.Mutex{}

	ctx := context.Background()
	client, err := h.HTTPClientConfig.CreateClient(ctx, h.Log)
	if err != nil {
		return err
	}

	h.client = client

	tomlCfg := &toml.Config{
		NormFieldName: toml.DefaultConfig.NormFieldName,
		FieldToKey:    toml.DefaultConfig.FieldToKey,
		// MissingField:  h.missingTomlField,
	}
	h.Toml = tomlCfg

	// Set default as [200]
	if len(h.SuccessStatusCodes) == 0 {
		h.SuccessStatusCodes = []int{200}
	}
	return nil
}

// LoadConfigData loads TOML-formatted config data
func (c *HTTP) LoadConfigData(data []byte) error {
	tbl, err := c.ParseConfig(data)
	if err != nil {
		return fmt.Errorf("error parsing data: %w", err)
	}

	// // Parse tags tables first:
	// for _, tableName := range []string{"tags", "global_tags"} {
	// 	if val, ok := tbl.Fields[tableName]; ok {
	// 		subTable, ok := val.(*ast.Table)
	// 		if !ok {
	// 			return fmt.Errorf("invalid configuration, bad table name %q", tableName)
	// 		}
	// 		if err = c.toml.UnmarshalTable(subTable, c.Tags); err != nil {
	// 			return fmt.Errorf("error parsing table name %q: %w", tableName, err)
	// 		}
	// 	}
	// }

	// // Parse agent table:
	// if val, ok := tbl.Fields["agent"]; ok {
	// 	subTable, ok := val.(*ast.Table)
	// 	if !ok {
	// 		return fmt.Errorf("invalid configuration, error parsing agent table")
	// 	}
	// 	if err = c.toml.UnmarshalTable(subTable, c.Agent); err != nil {
	// 		return fmt.Errorf("error parsing [agent]: %w", err)
	// 	}
	// }
	
	// if !c.Agent.OmitHostname {
	// 	if c.Agent.Hostname == "" {
	// 		hostname, err := os.Hostname()
	// 		if err != nil {
	// 			return err
	// 		}

	// 		c.Agent.Hostname = hostname
	// 	}

	// 	c.Tags["host"] = c.Agent.Hostname
	// }

	// // Warn when explicitly setting the old snmp translator
	// if c.Agent.SnmpTranslator == "netsnmp" {
	// 	models.PrintOptionValueDeprecationNotice(telegraf.Warn, "agent", "snmp_translator", "netsnmp", telegraf.DeprecationInfo{
	// 		Since:     "1.25.0",
	// 		RemovalIn: "2.0.0",
	// 		Notice:    "Use 'gosmi' instead",
	// 	})
	// }

	// // Setup the persister if requested
	// if c.Agent.Statefile != "" {
	// 	c.Persister = &persister.Persister{
	// 		Filename: c.Agent.Statefile,
	// 	}
	// }

	// if len(c.UnusedFields) > 0 {
	// 	return fmt.Errorf("line %d: configuration specified the fields %q, but they weren't used", tbl.Line, keys(c.UnusedFields))
	// }

	// // Initialize the file-sorting slices
	// c.fileProcessors = make(OrderedPlugins, 0)
	// c.fileAggProcessors = make(OrderedPlugins, 0)

	// Parse all the rest of the plugins:
	for name, val := range tbl.Fields {
		subTable, ok := val.(*ast.Table)
		if !ok {
			return fmt.Errorf("invalid configuration, error parsing field %q as table", name)
		}

		switch name {
		// case "agent", "global_tags", "tags":
		// case "outputs":
		// 	for pluginName, pluginVal := range subTable.Fields {
		// 		switch pluginSubTable := pluginVal.(type) {
		// 		// legacy [outputs.influxdb] support
		// 		case *ast.Table:
		// 			if err = c.addOutput(pluginName, pluginSubTable); err != nil {
		// 				return fmt.Errorf("error parsing %s, %w", pluginName, err)
		// 			}
		// 		case []*ast.Table:
		// 			for _, t := range pluginSubTable {
		// 				if err = c.addOutput(pluginName, t); err != nil {
		// 					return fmt.Errorf("error parsing %s array, %w", pluginName, err)
		// 				}
		// 			}
		// 		default:
		// 			return fmt.Errorf("unsupported config format: %s",
		// 				pluginName)
		// 		}
		// 		if len(c.UnusedFields) > 0 {
		// 			return fmt.Errorf("plugin %s.%s: line %d: configuration specified the fields %q, but they weren't used",
		// 				name, pluginName, subTable.Line, keys(c.UnusedFields))
		// 		}
		// 	}
		// case "inputs", "plugins":
		// 	for pluginName, pluginVal := range subTable.Fields {
		// 		switch pluginSubTable := pluginVal.(type) {
		// 		// legacy [inputs.cpu] support
		// 		case *ast.Table:
		// 			if err = c.addInput(pluginName, pluginSubTable); err != nil {
		// 				return fmt.Errorf("error parsing %s, %w", pluginName, err)
		// 			}
		// 		case []*ast.Table:
		// 			for _, t := range pluginSubTable {
		// 				if err = c.addInput(pluginName, t); err != nil {
		// 					return fmt.Errorf("error parsing %s, %w", pluginName, err)
		// 				}
		// 			}
		// 		default:
		// 			return fmt.Errorf("unsupported config format: %s",
		// 				pluginName)
		// 		}
		// 		if len(c.UnusedFields) > 0 {
		// 			return fmt.Errorf("plugin %s.%s: line %d: configuration specified the fields %q, but they weren't used",
		// 				name, pluginName, subTable.Line, keys(c.UnusedFields))
		// 		}
		// 	}
		case "processors":
			for pluginName, pluginVal := range subTable.Fields {
				switch pluginSubTable := pluginVal.(type) {
				case *ast.Table:
					if err = c.addProcessor(pluginName, pluginSubTable); err != nil {
						return fmt.Errorf("error parsing %s, %w", pluginName, err)
					}
				case []*ast.Table:
					for _, t := range pluginSubTable {
						if err = c.addProcessor(pluginName, t); err != nil {
							return fmt.Errorf("error parsing %s, %w", pluginName, err)
						}
					}
				default:
					return fmt.Errorf("unsupported config format: %s",
						pluginName)
				}
				if len(c.UnusedFields) > 0 {
					return fmt.Errorf(
						"plugin %s.%s: line %d: configuration specified the fields %q, but they weren't used",
						name,
						pluginName,
						subTable.Line,
						keys(c.UnusedFields),
					)
				}
			}
		// case "aggregators":
		// 	for pluginName, pluginVal := range subTable.Fields {
		// 		switch pluginSubTable := pluginVal.(type) {
		// 		case []*ast.Table:
		// 			for _, t := range pluginSubTable {
		// 				if err = c.addAggregator(pluginName, t); err != nil {
		// 					return fmt.Errorf("error parsing %s, %w", pluginName, err)
		// 				}
		// 			}
		// 		default:
		// 			return fmt.Errorf("unsupported config format: %s",
		// 				pluginName)
		// 		}
		// 		if len(c.UnusedFields) > 0 {
		// 			return fmt.Errorf("plugin %s.%s: line %d: configuration specified the fields %q, but they weren't used",
		// 				name, pluginName, subTable.Line, keys(c.UnusedFields))
		// 		}
		// 	}
		// case "secretstores":
		// 	for pluginName, pluginVal := range subTable.Fields {
		// 		switch pluginSubTable := pluginVal.(type) {
		// 		case []*ast.Table:
		// 			for _, t := range pluginSubTable {
		// 				if err = c.addSecretStore(pluginName, t); err != nil {
		// 					return fmt.Errorf("error parsing %s, %w", pluginName, err)
		// 				}
		// 			}
		// 		default:
		// 			return fmt.Errorf("unsupported config format: %s", pluginName)
		// 		}
		// 		if len(c.UnusedFields) > 0 {
		// 			msg := "plugin %s.%s: line %d: configuration specified the fields %q, but they weren't used"
		// 			return fmt.Errorf(msg, name, pluginName, subTable.Line, keys(c.UnusedFields))
		// 		}
		// 	}

		// Assume it's an input for legacy config file support if no other
		// identifiers are present
		default:
			// if err = c.addInput(name, subTable); err != nil {
			// 	return fmt.Errorf("error parsing %s, %w", name, err)
			// }
		}
	}

	// // Sort the processor according to the order they appeared in this file
	// // In a later stage, we sort them using the `order` option.
	// sort.Sort(c.fileProcessors)
	// for _, op := range c.fileProcessors {
	// 	c.Processors = append(c.Processors, op.plugin.(*models.RunningProcessor))
	// }

	// sort.Sort(c.fileAggProcessors)
	// for _, op := range c.fileAggProcessors {
	// 	c.AggProcessors = append(c.AggProcessors, op.plugin.(*models.RunningProcessor))
	// }

	return nil
}

// parseConfig loads a TOML configuration from a provided path and
// returns the AST produced from the TOML parser. When loading the file, it
// will find environment variables and replace them.
func (h *HTTP) ParseConfig(contents []byte) (*ast.Table, error) {
	contents = trimBOM(contents)

	parameters := envVarRe.FindAllSubmatch(contents, -1)
	for _, parameter := range parameters {
		if len(parameter) != 3 {
			continue
		}

		var envVar []byte
		if parameter[1] != nil {
			envVar = parameter[1]
		} else if parameter[2] != nil {
			envVar = parameter[2]
		} else {
			continue
		}

		envVal, ok := os.LookupEnv(strings.TrimPrefix(string(envVar), "$"))
		if ok {
			envVal = escapeEnv(envVal)
			contents = bytes.Replace(contents, parameter[0], []byte(envVal), 1)
		}
	}

	return toml.Parse(contents)
}

func (c *HTTP) addProcessor(name string, table *ast.Table) error {
	creator, ok := processors.Processors[name]
	if !ok {
		// // Handle removed, deprecated plugins
		// if di, deprecated := processors.Deprecations[name]; deprecated {
		// 	printHistoricPluginDeprecationNotice("processors", name, di)
		// 	return fmt.Errorf("plugin deprecated")
		// }
		return fmt.Errorf("undefined but requested processor: %s", name)
	}

	var method string
	c.getFieldString(table, "method", &method)
	var body string
	c.getFieldString(table, "body", &body)


	// For processors with parsers we need to compute the set of
	// options that is not covered by both, the parser and the processor.
	// We achieve this by keeping a local book of missing entries
	// that counts the number of misses. In case we have a parser
	// for the input both need to miss the entry. We count the
	// missing entries at the end.
	missCount := make(map[string]int)
	missCountThreshold := 0
	c.setLocalMissingTomlFieldTracker(missCount)
	defer c.resetMissingTomlFieldTracker()

	// Setup the processor running before the aggregators
	processorBeforeConfig, err := c.buildProcessor("processors", name, table)
	if err != nil {
		return err
	}
	// processorBefore, hasParser, err := c.setupProcessor(processorBeforeConfig.Name, creator, table)
	_, hasParser, err := c.setupProcessor(processorBeforeConfig.Name, creator, table)
	if err != nil {
		return err
	}
	// rf := models.NewRunningProcessor(processorBefore, processorBeforeConfig)
	// c.fileProcessors = append(c.fileProcessors, &OrderedPlugin{table.Line, rf})

	// Setup another (new) processor instance running after the aggregator
	processorAfterConfig, err := c.buildProcessor("aggprocessors", name, table)
	if err != nil {
		return err
	}
	// processorAfter, _, err := c.setupProcessor(processorAfterConfig.Name, creator, table)
	_, _, err = c.setupProcessor(processorAfterConfig.Name, creator, table)
	if err != nil {
		return err
	}
	// rf = models.NewRunningProcessor(processorAfter, processorAfterConfig)
	// c.fileAggProcessors = append(c.fileAggProcessors, &OrderedPlugin{table.Line, rf})

	// input := creator()
	// if err := c.Toml.UnmarshalTable(table, input); err != nil {
	if err := c.Toml.UnmarshalTable(table, c); err != nil {
		return err
	}
	
	
	// Check the number of misses against the threshold
	if hasParser {
		missCountThreshold = 2
	}
	for key, count := range missCount {
		if count <= missCountThreshold {
			continue
		}
		if err := c.missingTomlField(nil, key); err != nil {
			return err
		}
	}

	return nil
}

// buildProcessor parses Processor specific items from the ast.Table,
// builds the filter and returns a
// models.ProcessorConfig to be inserted into models.RunningProcessor
func (c *HTTP) buildProcessor(category, name string, tbl *ast.Table) (*models.ProcessorConfig, error) {
	conf := &models.ProcessorConfig{Name: name}

	c.getFieldInt64(tbl, "order", &conf.Order)
	c.getFieldString(tbl, "alias", &conf.Alias)

	// if c.hasErrs() {
	// 	return nil, c.firstErr()
	// }

	var err error
	// conf.Filter, err = c.buildFilter(tbl)
	// if err != nil {
	// 	return conf, err
	// }

	// // Generate an ID for the plugin
	// conf.ID, err = generatePluginID(category+"."+name, tbl)
	conf.ID, err = GeneratePluginID(category+"."+name, tbl)
	return conf, err
}

func (c *HTTP) setupProcessor(name string, creator processors.StreamingCreator, table *ast.Table) (telegraf.StreamingProcessor, bool, error) {
	var hasParser bool

	streamingProcessor := creator()

	var processor interface{}
	if p, ok := streamingProcessor.(unwrappable); ok {
		processor = p.Unwrap()
	} else {
		processor = streamingProcessor
	}

	// If the (underlying) processor has a SetParser or SetParserFunc function,
	// it can accept arbitrary data-formats, so build the requested parser and
	// set it.
	if t, ok := processor.(telegraf.ParserPlugin); ok {
		parser, err := c.addParser("processors", name, table)
		if err != nil {
			return nil, true, fmt.Errorf("adding parser failed: %w", err)
		}
		t.SetParser(parser)
		hasParser = true
	}

	if t, ok := processor.(telegraf.ParserFuncPlugin); ok {
		if !c.probeParser("processors", name, table) {
			return nil, false, errors.New("parser not found")
		}
		t.SetParserFunc(func() (telegraf.Parser, error) {
			return c.addParser("processors", name, table)
		})
		hasParser = true
	}

	if err := c.Toml.UnmarshalTable(table, processor); err != nil {
		return nil, hasParser, fmt.Errorf("unmarshalling failed: %w", err)
	}

	// err := c.printUserDeprecation("processors", name, processor)
	var err error
	err = nil
	return streamingProcessor, hasParser, err
}

func (c *HTTP) probeParser(parentcategory string, parentname string, table *ast.Table) bool {
	var dataformat string
	c.getFieldString(table, "data_format", &dataformat)
	if dataformat == "" {
		dataformat = setDefaultParser(parentcategory, parentname)
	}

	creator, ok := parsers.Parsers[dataformat]
	if !ok {
		return false
	}

	// Try to parse the options to detect if any of them is misspelled
	// We don't actually use the parser, so no need to check the error.
	parser := creator("")
	_ = c.Toml.UnmarshalTable(table, parser)

	return true
}

func (c *HTTP) addParser(parentcategory, parentname string, table *ast.Table) (*models.RunningParser, error) {
	var dataformat string
	c.getFieldString(table, "data_format", &dataformat)
	if dataformat == "" {
		dataformat = setDefaultParser(parentcategory, parentname)
	}

	var influxParserType string
	c.getFieldString(table, "influx_parser_type", &influxParserType)
	if dataformat == "influx" && influxParserType == "upstream" {
		dataformat = "influx_upstream"
	}

	creator, ok := parsers.Parsers[dataformat]
	if !ok {
		return nil, fmt.Errorf("undefined but requested parser: %s", dataformat)
	}
	parser := creator(parentname)

	// Handle reset-mode of CSV parsers to stay backward compatible (see issue #12022)
	if dataformat == "csv" && parentcategory == "inputs" {
		if parentname == "exec" {
			csvParser := parser.(*csv.Parser)
			csvParser.ResetMode = "always"
		}
	}

	conf := c.buildParser(parentname, table)
	if err := c.Toml.UnmarshalTable(table, parser); err != nil {
		return nil, err
	}

	running := models.NewRunningParser(parser, conf)
	err := running.Init()
	return running, err
}

// Gather takes in an accumulator and adds the metrics that the Input
// gathers. This is called every "interval"
func (h *HTTP) Gather(acc telegraf.Accumulator) error {
	var wg sync.WaitGroup
	for _, u := range h.URLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			if err := h.gatherURL(acc, url); err != nil {
				acc.AddError(fmt.Errorf("[url=%s]: %w", url, err))
			}
		}(u)
	}

	wg.Wait()

	return nil
}

// SetParserFunc takes the data_format from the config and finds the right parser for that format
func (h *HTTP) SetParserFunc(fn telegraf.ParserFunc) {
	h.parserFunc = fn
}

func (e *HTTP) SetParser(p telegraf.Parser) {
	e.parser = p
}

func setDefaultParser(category string, name string) string {
	// Legacy support, exec plugin originally parsed JSON by default.
	if category == "inputs" && name == "exec" {
		return "json"
	}

	// return "influx"
	return "json"
}

func (c *HTTP) AddParser(parentcategory, parentname string, table *ast.Table) (*models.RunningParser, error) {
	var dataformat string
	// c.getFieldString(table, "data_format", &dataformat)
	dataformat = c.DataFormat
	if dataformat == "" {
		dataformat = setDefaultParser(parentcategory, parentname)
	}

	// var influxParserType string
	// c.getFieldString(table, "influx_parser_type", &influxParserType)
	// if dataformat == "influx" && influxParserType == "upstream" {
	// 	dataformat = "influx_upstream"
	// }

	creator, ok := parsers.Parsers[dataformat]
	if !ok {
		return nil, fmt.Errorf("undefined but requested parser: %s", dataformat)
	}
	parser := creator(parentname)

	// Handle reset-mode of CSV parsers to stay backward compatible (see issue #12022)
	if dataformat == "csv" && parentcategory == "inputs" {
		if parentname == "exec" {
			csvParser := parser.(*csv.Parser)
			csvParser.ResetMode = "always"
		}
	}

	conf := c.buildParser(parentname, table)
	if err := c.Toml.UnmarshalTable(table, parser); err != nil {
		return nil, err
	}

	running := models.NewRunningParser(parser, conf)
	err := running.Init()
	return running, err
}

// buildParser parses Parser specific items from the ast.Table,
// builds the filter and returns a
// models.ParserConfig to be inserted into models.RunningParser
func (c *HTTP) buildParser(name string, tbl *ast.Table) *models.ParserConfig {
	var dataFormat string
	c.getFieldString(tbl, "data_format", &dataFormat)

	conf := &models.ParserConfig{
		Parent:     name,
		DataFormat: dataFormat,
	}

	return conf
}

func (c *HTTP) setLocalMissingTomlFieldTracker(counter map[string]int) {
	f := func(t reflect.Type, key string) error {
		// Check if we are in a root element that might share options among
		// each other. Those root elements are plugins of all types.
		// All other elements are subtables of their respective plugin and
		// should just be hit once anyway. Therefore, we mark them with a
		// high number to handle them correctly later.
		pt := reflect.PtrTo(t)
		root := pt.Implements(reflect.TypeOf((*telegraf.Input)(nil)).Elem())
		root = root || pt.Implements(reflect.TypeOf((*telegraf.ServiceInput)(nil)).Elem())
		root = root || pt.Implements(reflect.TypeOf((*telegraf.Output)(nil)).Elem())
		root = root || pt.Implements(reflect.TypeOf((*telegraf.Aggregator)(nil)).Elem())
		root = root || pt.Implements(reflect.TypeOf((*telegraf.Processor)(nil)).Elem())
		root = root || pt.Implements(reflect.TypeOf((*telegraf.Parser)(nil)).Elem())

		c, ok := counter[key]
		if !root {
			counter[key] = 100
		} else if !ok {
			counter[key] = 1
		} else {
			counter[key] = c + 1
		}
		return nil
	}
	c.Toml.MissingField = f
}

func (c *HTTP) resetMissingTomlFieldTracker() {
	c.Toml.MissingField = c.missingTomlField
}

func (c *HTTP) getFieldString(tbl *ast.Table, fieldName string, target *string) {
	if node, ok := tbl.Fields[fieldName]; ok {
		if kv, ok := node.(*ast.KeyValue); ok {
			if str, ok := kv.Value.(*ast.String); ok {
				*target = str.Value
			}
		}
	}
}

func (c *HTTP) getFieldInt64(tbl *ast.Table, fieldName string, target *int64) {
	if node, ok := tbl.Fields[fieldName]; ok {
		if kv, ok := node.(*ast.KeyValue); ok {
			if iAst, ok := kv.Value.(*ast.Integer); ok {
				i, err := iAst.Int()
				if err != nil {
					c.addError(tbl, fmt.Errorf("unexpected int type %q, expecting int", iAst.Value))
					return
				}
				*target = i
			} else {
				c.addError(tbl, fmt.Errorf("found unexpected format while parsing %q, expecting int", fieldName))
			}
		}
	}
}

// Gathers data from a particular URL
// Parameters:
//
//	acc    : The telegraf Accumulator to use
//	url    : endpoint to send request to
//
// Returns:
//
//	error: Any error that may have occurred
func (h *HTTP) gatherURL(
	acc telegraf.Accumulator,
	url string,
) error {
	body := makeRequestBodyReader(h.ContentEncoding, h.Body)
	request, err := http.NewRequest(h.Method, url, body)
	if err != nil {
		return err
	}

	if h.BearerToken != "" {
		token, err := os.ReadFile(h.BearerToken)
		if err != nil {
			return err
		}
		bearer := "Bearer " + strings.Trim(string(token), "\n")
		request.Header.Set("Authorization", bearer)
	}

	// if h.ContentEncoding == "gzip" {
	// 	request.Header.Set("Content-Encoding", "gzip")
	// }

	for k, v := range h.Headers {
		if strings.ToLower(k) == "host" {
			request.Host = v
		} else {
			request.Header.Add(k, v)
		}
	}

	if err := h.setRequestAuth(request); err != nil {
		return err
	}

	resp, err := h.client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	responseHasSuccessCode := false
	for _, statusCode := range h.SuccessStatusCodes {
		if resp.StatusCode == statusCode {
			responseHasSuccessCode = true
			break
		}
	}

	if !responseHasSuccessCode {
		return fmt.Errorf("received status code %d (%s), expected any value out of %v",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
			h.SuccessStatusCodes)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading body failed: %w", err)
	}

	// Instantiate a new parser for the new data to avoid trouble with stateful parsers
	parser, err := h.parserFunc()
	if err != nil {
		return fmt.Errorf("instantiating parser failed: %w", err)
	}
	metrics, err := parser.Parse(b)
	if err != nil {
		return fmt.Errorf("parsing metrics failed: %w", err)
	}

	for _, metric := range metrics {
		if !metric.HasTag("url") {
			metric.AddTag("url", url)
		}
		acc.AddFields(metric.Name(), metric.Fields(), metric.Tags(), metric.Time())
	}

	return nil
}

func (h *HTTP) setRequestAuth(request *http.Request) error {
	if h.Username.Empty() && h.Password.Empty() {
		return nil
	}

	username, err := h.Username.Get()
	if err != nil {
		return fmt.Errorf("getting username failed: %w", err)
	}
	defer config.ReleaseSecret(username)

	password, err := h.Password.Get()
	if err != nil {
		return fmt.Errorf("getting password failed: %w", err)
	}
	defer config.ReleaseSecret(password)

	request.SetBasicAuth(string(username), string(password))

	return nil
}

func (c *HTTP) hasErrs() bool {
	return len(c.errs) > 0
}

func (c *HTTP) addError(tbl *ast.Table, err error) {
	c.errs = append(c.errs, fmt.Errorf("line %d:%d: %w", tbl.Line, tbl.Position, err))
}

func (e *HTTP) Start(acc telegraf.Accumulator) error {
	// var err error
	// e.serializer, err = serializers.NewSerializer(e.serializerConfig)
	// if err != nil {
	// 	return fmt.Errorf("error creating serializer: %w", err)
	// }
	// e.acc = acc

	// e.process, err = process.New(e.Command, e.Environment)
	// if err != nil {
	// 	return fmt.Errorf("error creating new process: %w", err)
	// }
	// e.process.Log = e.Log
	// e.process.RestartDelay = time.Duration(e.RestartDelay)
	// e.process.ReadStdoutFn = e.cmdReadOut
	// e.process.ReadStderrFn = e.cmdReadErr

	// if err = e.process.Start(); err != nil {
	// 	// if there was only one argument, and it contained spaces, warn the user
	// 	// that they may have configured it wrong.
	// 	if len(e.Command) == 1 && strings.Contains(e.Command[0], " ") {
	// 		e.Log.Warn("The processors.execd Command contained spaces but no arguments. " +
	// 			"This setting expects the program and arguments as an array of strings, " +
	// 			"not as a space-delimited string. See the plugin readme for an example.")
	// 	}
	// 	return fmt.Errorf("failed to start process %s: %w", e.Command, err)
	// }

	return nil
}

func (e *HTTP) Add(m telegraf.Metric, _ telegraf.Accumulator) error {
	// b, err := e.serializer.Serialize(m)
	// if err != nil {
	// 	return fmt.Errorf("metric serializing error: %w", err)
	// }

	// _, err = e.process.Stdin.Write(b)
	// if err != nil {
	// 	return fmt.Errorf("error writing to process stdin: %w", err)
	// }

	// // We cannot maintain tracking metrics at the moment because input/output
	// // is done asynchronously and we don't have any metric metadata to tie the
	// // output metric back to the original input metric.
	// m.Drop()
	return nil
}

func (e *HTTP) Stop() {
	// e.process.Stop()
}

func (c *HTTP) missingTomlField(_ reflect.Type, key string) error {
	switch key {
	// General options to ignore
	case "alias",
		"collection_jitter", "collection_offset",
		"data_format", "delay", "drop", "drop_original",
		"fielddrop", "fieldpass", "flush_interval", "flush_jitter",
		"grace",
		"interval",
		"lvm", // What is this used for?
		"metric_batch_size", "metric_buffer_limit",
		"name_override", "name_prefix", "name_suffix", "namedrop", "namepass",
		"order",
		"method", "urls",
		"pass", "period", "precision",
		"tagdrop", "tagexclude", "taginclude", "tagpass", "tags":

	// Secret-store options to ignore
	case "id":

	// Parser options to ignore
	case "data_type", "influx_parser_type":

	// Serializer options to ignore
	case "prefix", "template", "templates", "xpath",
		"carbon2_format", "carbon2_sanitize_replace_char",
		"csv_column_prefix", "csv_header", "csv_separator", "csv_timestamp_format",
		"graphite_strict_sanitize_regex",
		"graphite_tag_sanitize_mode", "graphite_tag_support", "graphite_separator",
		"influx_max_line_bytes", "influx_sort_fields", "influx_uint_support",
		"json_timestamp_format", "json_timestamp_units", "json_transformation",
		"json_nested_fields_include", "json_nested_fields_exclude",
		"prometheus_export_timestamp", "prometheus_sort_metrics", "prometheus_string_as_label",
		"prometheus_compact_encoding",
		"splunkmetric_hec_routing", "splunkmetric_multimetric", "splunkmetric_omit_event_tag",
		"wavefront_disable_prefix_conversion", "wavefront_source_override", "wavefront_use_strict":
	default:
		c.unusedFieldsMutex.Lock()
		c.UnusedFields[key] = true
		c.unusedFieldsMutex.Unlock()
	}
	return nil
}

func makeRequestBodyReader(contentEncoding, body string) io.Reader {
	if body == "" {
		return nil
	}

	var reader io.Reader = strings.NewReader(body)
	// if contentEncoding == "gzip" {
	// 	return internal.CompressWithGzip(reader)
	// }

	return reader
}

func init() {
	processors.AddStreaming("http", func() telegraf.StreamingProcessor {
		return &HTTP{
			Method: "GET",
			serializerConfig: &serializers.Config{
				DataFormat: "influx",
			},
		}
	})
}

func trimBOM(f []byte) []byte {
	return bytes.TrimPrefix(f, []byte("\xef\xbb\xbf"))
}

// escapeEnv escapes a value for inserting into a TOML string.
func escapeEnv(value string) string {
	return envVarEscaper.Replace(value)
}

// unwrappable lets you retrieve the original telegraf.Processor from the
// StreamingProcessor. This is necessary because the toml Unmarshaller won't
// look inside composed types.
type unwrappable interface {
	Unwrap() telegraf.Processor
}

func keys(m map[string]bool) []string {
	result := []string{}
	for k := range m {
		result = append(result, k)
	}
	return result
}
