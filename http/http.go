//go:generate ../../../tools/readme_config_includer/generator
package http

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/toml"

	httpconfig "github.com/influxdata/telegraf/plugins/common/http"
	_ "github.com/influxdata/telegraf/plugins/parsers/xpath"
	"github.com/influxdata/telegraf/plugins/inputs"
	"github.com/influxdata/telegraf/plugins/serializers"
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
	Toml              *toml.Config
	errs              []error // config load errors.

	httpconfig.HTTPClientConfig
	serializerConfig *serializers.Config
	serializer       serializers.Serializer

	client     *http.Client
	parser     telegraf.Parser
	parserFunc telegraf.ParserFunc
}

func (*HTTP) SampleConfig() string {
	return sampleConfig
}

func (h *HTTP) Init() error {
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
	inputs.Add("http", func() telegraf.Input {
		return &HTTP{
			Method: "GET",
			serializerConfig: &serializers.Config{
				DataFormat: "influx",
			},
		}
	})
}
