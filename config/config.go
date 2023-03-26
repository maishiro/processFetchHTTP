package config

import (
	"bytes"
	"os"
	"strings"

	"github.com/BurntSushi/toml"

	cfgHTTP "processFetchHTTP/HTTP"
)

var (
	envVarEscaper = strings.NewReplacer(
		`"`, `\"`,
		`\`, `\\`,
	)
)

type Config struct {
	// Cfg ConfigMain `toml:"config"`
	Cfg cfgHTTP.HTTP `toml:"config"`
}

//type ConfigMain struct {
//	LogFilePath      string `toml:"logfile_path"`
//	LogFileMaxSize   int    `toml:"logfile_maxsize"`
//	LogFileMaxBackup int    `toml:"logfile_maxbackup"`
//	LogFileMaxAge    int    `toml:"logfile_maxage"`
//
//	// Driver           string `toml:"driver"`
//	// ConnectionString string `toml:"connection_string"`
//
//	// Items []configItem `toml:"item"`
//
//	URLs            []string `toml:"urls"`
//	Method          string   `toml:"method"`
//	Body            string   `toml:"body"`
//	ContentEncoding string   `toml:"content_encoding"`
//
//	Headers map[string]string `toml:"headers"`
//
//	// HTTP Basic Auth Credentials
//	// Username config.Secret `toml:"username"`
//	// Password config.Secret `toml:"password"`
//
//	// Absolute path to file with Bearer token
//	BearerToken string `toml:"bearer_token"`
//
//	SuccessStatusCodes []int `toml:"success_status_codes"`
//
//	Log telegraf.Logger `toml:"-"`
//
//	httpconfig.HTTPClientConfig
//
//	client     *http.Client
//	parserFunc telegraf.ParserFunc
//}

type configItem struct {
	ID             string            `toml:"id"`
	SqlTemplate    string            `toml:"sql_template"`
	Tags           []string          `toml:"tag_columns"`
	ExcludeColumns []string          `toml:"exclude_columns"`
	ColumnTypes    map[string]string `toml:"column_types"`
}

func NewConfig() *Config {
	c := &Config{}
	return c
}

func (c *Config) LoadConfig(path string) error {
	var err error
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	s := expandEnvVars(b)

	_, err = toml.Decode(s, c)
	if err != nil {
		return err
	}

	c.Cfg.Init()

	// _, err = c.Cfg.ParseConfig(b)
	// if err != nil {
	// 	// return fmt.Errorf("error parsing data: %w", err)
	// 	return err
	// }
	err = c.Cfg.LoadConfigData(b)
	if err != nil {
		// return fmt.Errorf("error parsing data: %w", err)
		return err
	}

	// if val, ok := tbl.Fields["config"]; ok {
	// 	subTable, ok := val.(*ast.Table)
	// 	if !ok {
	// 		// return fmt.Errorf("invalid configuration, error parsing agent table")
	// 		return fmt.Errorf("invalid configuration, error parsing agent table")
	// 	}
	// 	// if err = c.toml.UnmarshalTable(subTable, c.Agent); err != nil {
	// 	Tags := make(map[string]string)
	// 	tml := tt.Config{}
	// 	if err = tml.UnmarshalTable(subTable, Tags); err != nil {
	// 		return fmt.Errorf("error parsing [agent]: %w", err)
	// 	}
	// }

	return nil
}

func trimBOM(f []byte) []byte {
	return bytes.TrimPrefix(f, []byte("\xef\xbb\xbf"))
}

func expandEnvVars(contents []byte) string {
	return os.Expand(string(contents), getEnv)
}

func getEnv(key string) string {
	v := os.Getenv(key)

	return envVarEscaper.Replace(v)
}
