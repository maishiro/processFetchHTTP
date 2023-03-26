package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"reflect"
	"regexp"
	"strconv"

	"processFetchHTTP/config"

	lumberjack "gopkg.in/natefinch/lumberjack.v2"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/agent"
	"github.com/influxdata/telegraf/plugins/parsers/influx"

	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/godror/godror"
	_ "github.com/lib/pq"
	_ "github.com/mattn/go-sqlite3"
)

func main() {
	pszPathConfig := flag.String("config", "./setting.conf", "-config (file path)")
	flag.Parse()
	strPathConfig := *pszPathConfig

	// load configuration
	cfg := config.NewConfig()
	err := cfg.LoadConfig(strPathConfig)
	if err != nil {
		log.Printf("Failed to load config file: %v\n", err)
		return
	}

	// LOG configuration
	log.SetOutput(&lumberjack.Logger{
		Filename:   cfg.Setting.LogFilePath,
		MaxSize:    cfg.Setting.LogFileMaxSize,
		MaxBackups: cfg.Setting.LogFileMaxBackup,
		MaxAge:     cfg.Setting.LogFileMaxAge,
		Compress:   false,
	})

	// if len(cfg.Cfg.Items) == 0 {
	// 	log.Println("Nothing observe item")
	// 	return
	// }

	// serializer := serializers.NewInfluxSerializer()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)

	done := make(chan string)
	go func() {
		// cfg.Cfg.Init()

		// table := &ast.Table{}
		// name := "config"

		// cfg.Cfg.SetParserFunc(func() (telegraf.Parser, error) {
		// 	return cfg.Cfg.AddParser("config", name, table)
		// })

		for {
			metrics := make(chan telegraf.Metric, 10)
			defer close(metrics)
			acc := agent.NewAccumulator(&TestMetricMaker{}, metrics)

			var sc = bufio.NewScanner(os.Stdin)
			if sc.Scan() {
				line := sc.Text()
				log.Printf("Input: [%s]\n", line)

				parser := influx.Parser{}
				parser.Init()
				metric, err := parser.ParseLine(line)
				if err != nil {
					log.Printf("Parse Error: %V [%s]\n", err, line)
					continue
				}

				var kk []*regexp.Regexp
				var vv []string
				for _, v := range metric.TagList() {
					rep := regexp.MustCompile(fmt.Sprintf("@%s", v.Key))
					kk = append(kk, rep)
					vv = append(vv, fmt.Sprintf("%v", v.Value))
				}
				for _, v := range metric.FieldList() {
					rep := regexp.MustCompile(fmt.Sprintf("@%s", v.Key))
					kk = append(kk, rep)
					vv = append(vv, fmt.Sprintf("%v", v.Value))
				}

				err = cfg.Cfg.Gather(acc)

				// driverName := cfg.Cfg.Driver
				// connStr := cfg.Cfg.ConnectionString
				// engine, err := xorm.NewEngine(driverName, connStr)
				// if err != nil {
				// 	log.Printf("Failed to open target DB: %v\n", err)
				// 	continue
				// }
				// defer engine.Close()

				// for i := 0; i < len(cfg.Cfg.Items); i++ {
				// 	id := cfg.Cfg.Items[i].ID
				// 	strFmtSQL := cfg.Cfg.Items[i].SqlTemplate
				// 	tags := cfg.Cfg.Items[i].Tags
				// 	mapTags := make(map[string]string)
				// 	for _, v := range tags {
				// 		mapTags[v] = ""
				// 	}
				// 	excludes := cfg.Cfg.Items[i].ExcludeColumns
				// 	mapExcludes := make(map[string]string)
				// 	for _, v := range excludes {
				// 		mapExcludes[v] = ""
				// 	}
				// 	colTypes := cfg.Cfg.Items[i].ColumnTypes

				// 	// Replace
				// 	for i, v := range kk {
				// 		strFmtSQL = v.ReplaceAllString(strFmtSQL, vv[i])
				// 	}
				// 	strSQL := strFmtSQL

				// 	results, err := engine.QueryInterface(strSQL)
				// 	if err != nil {
				// 		log.Printf("Failed to query: %v [%s]\n", err, strSQL)
				// 		continue
				// 	}
				// 	for _, vs := range results {
				// 		tags := make(map[string]string)
				// 		field := make(map[string]interface{})
				// 		for k, v := range vs {
				// 			// Check NOT NULL
				// 			if len(k) == 0 || v == nil {
				// 				continue
				// 			}

				// 			strValue := ToString(v)
				// 			if _, ok := mapTags[k]; ok {
				// 				tags[k] = strValue
				// 			} else if _, ok := mapExcludes[k]; !ok {
				// 				if colType, ok := colTypes[k]; ok {
				// 					field[k] = parseValue(strValue, colType)
				// 				} else {
				// 					switch t := v.(type) {
				// 					case string:
				// 						field[k] = t
				// 					case []uint8:
				// 						field[k] = string(t)
				// 					case int32:
				// 						field[k] = int(t)
				// 					case float64:
				// 						field[k] = float64(t)
				// 					default:
				// 						log.Printf("default type: %s\n", t)
				// 						log.Printf("default type: %v\n", t)
				// 						field[k] = fmt.Sprintf("%v", t)
				// 					}
				// 				}
				// 			}
				// 		}

				// 		mtx := metric.Copy()
				// 		mtx.SetName(id)
				// 		for _, v := range metric.FieldList() {
				// 			mtx.RemoveField(v.Key)
				// 		}

				// 		for k, v := range tags {
				// 			mtx.AddTag(k, v)
				// 		}
				// 		for k, v := range field {
				// 			mtx.AddField(k, v)
				// 		}

				// 		b, err := serializer.Serialize(mtx)
				// 		if err != nil {
				// 			log.Printf("ERR %v\n", err)
				// 			continue
				// 		}
				// 		outline := string(b)
				// 		log.Printf("output %s\n", outline)
				// 		fmt.Fprint(os.Stdout, outline)
				// 	}
				// }
			} else {
				done <- "done"
			}
			if sc.Err() != nil {
				done <- "done"
				break
			}
		}
	}()

	select {
	case <-quit:
	case <-done:
	}
}

func ToString(v interface{}) string {
	strValue := ""
	switch t := v.(type) {
	case string:
		strValue = t
	case []uint8:
		strValue = string(t)
	case int32:
		strValue = fmt.Sprint(int(t))
	case float64:
		strValue = fmt.Sprint(float64(t))
	default:
		log.Printf("default type: %s\n", t)
		log.Printf("default type: %v\n", t)
		strValue = fmt.Sprintf("%v", t)
	}
	return strValue
}

func parseValue(strValue string, colType string) interface{} {
	var result interface{}
	switch colType {
	case "int":
		vi, err := strconv.Atoi(strValue)
		if err == nil {
			result = vi
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "int32":
		i32, err := strconv.ParseInt(strValue, 10, 32)
		if err == nil {
			result = i32
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "int64":
		i64, err := strconv.ParseInt(strValue, 10, 64)
		if err == nil {
			result = i64
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "uint":
		ui64, err := strconv.ParseUint(strValue, 10, 64)
		if err == nil {
			result = ui64
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "uint32":
		ui, err := strconv.ParseUint(strValue, 10, 32)
		if err == nil {
			result = ui
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "uint64":
		ui, err := strconv.ParseUint(strValue, 10, 64)
		if err == nil {
			result = ui
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "float32":
		f32, err := strconv.ParseFloat(strValue, 32)
		if err == nil {
			result = f32
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	case "float64":
		f64, err := strconv.ParseFloat(strValue, 64)
		if err == nil {
			result = f64
		} else {
			log.Printf("Failed to parse(%s): (%v)\n", colType, strValue)
			result = strValue
		}
	default:
		result = strValue
	}
	return result
}

func JsonString(v interface{}) string {
	strJSON := ""
	b, err := json.Marshal(v)
	if err == nil {
		strJSON = string(b)
	}
	return strJSON
}

func DeepEqualJSON(j1, j2 string) (bool, error) {
	var err error

	var d1 interface{}
	err = json.Unmarshal([]byte(j1), &d1)
	if err != nil {
		return false, err
	}

	var d2 interface{}
	err = json.Unmarshal([]byte(j2), &d2)
	if err != nil {
		return false, err
	}

	if reflect.DeepEqual(d1, d2) {
		return true, nil
	} else {
		return false, nil
	}
}

func IsEqualJSON(a, b string) bool {
	bEqual, _ := DeepEqualJSON(a, b)
	return bEqual
}

type TestMetricMaker struct {
}

func (tm *TestMetricMaker) Name() string {
	return "TestPlugin"
}

func (tm *TestMetricMaker) LogName() string {
	return tm.Name()
}

func (tm *TestMetricMaker) MakeMetric(metric telegraf.Metric) telegraf.Metric {
	return metric
}

func (tm *TestMetricMaker) Log() telegraf.Logger {
	// return models.NewLogger("TestPlugin", "test", "")
	return nil
}
