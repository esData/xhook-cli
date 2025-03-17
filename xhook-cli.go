// XHOOK-CLI

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"esdata.co/xhook-control/xhook-cli/banner"
	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/perimeterx/marshmallow"
	"github.com/urfave/cli/v2"
	"gitlab.com/david_mbuvi/go_asterisks"
)

const Org = "unset_org"
const Proj = "undef_proj"
const Uri = ""

type User_options struct {
	Proj string
}

type User struct {
	Email           string
	Organisation    string
	Last_login_time string
	Options         User_options
}

type Auth_Info struct {
	Status bool
	User   User
}

type Workflow struct {
	Name        string
	Summary     string
	Publish     string
	Tags        []string
	Parameters  map[string]json.RawMessage
	Steps       map[string]json.RawMessage
	Trigger     map[string]json.RawMessage
	Invokes     []string
	Description string
	UpdatedAt   time.Time
}

type Workflow_run struct {
	Id      string
	Message string
	// Result  map[string][]map[string]string `json:"result,omitempty"`
	Result map[string]json.RawMessage `json:"result,omitempty"`
}

var (
	user     = ""
	password = ""
	homedir  = ""

	auth_info           Auth_Info
	org                 = Org
	proj                = Proj
	options             = ""
	token               = ""
	lifetime            = ""
	loglevel            = "info"
	workflow_id         = ""
	payload             = ""
	workflow_name       = ""
	workflow_parameters = ""
	workflow            Workflow
	workflows           []Workflow
	workflow_run        Workflow_run
	user_options        User_options
	uri                 = "https://xhook-api.esdata.io:8443"
	exitCode            = 0
	json_format         = false
	file_output         = ""
)

func connect(clientId string, uri *url.URL) mqtt.Client {
	opts := createClientOptions(clientId, uri)
	client := mqtt.NewClient(opts)
	token := client.Connect()
	for !token.WaitTimeout(3 * time.Second) {
	}
	if err := token.Error(); err != nil {
		//slog.Error(err)
	}
	return client
}

func createClientOptions(clientId string, uri *url.URL) *mqtt.ClientOptions {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(fmt.Sprintf("tcp://%s", uri.Host))
	opts.SetUsername(uri.User.Username())
	password, _ := uri.User.Password()
	opts.SetPassword(password)
	opts.SetClientID(clientId)
	return opts
}

func listen(uri *url.URL, topic string) {
	client := connect("sub", uri)
	client.Subscribe(topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		slog.Info("* [%s] %s\n", msg.Topic(), string(msg.Payload()))
	})
}

func setParams() {
	if loglevel == "info" {
		slog.SetLogLoggerLevel(slog.LevelInfo)
	} else if loglevel == "error" {
		slog.SetLogLoggerLevel(slog.LevelError)
		slog.Info("[SYS] loglevel=[" + loglevel + "]")
	} else if loglevel == "warn" {
		slog.SetLogLoggerLevel(slog.LevelWarn)
		slog.Info("[SYS] loglevel=[" + loglevel + "]")
	} else if loglevel == "debug" {
		slog.SetLogLoggerLevel(slog.LevelDebug)
		slog.Info("[SYS] loglevel=[" + loglevel + "]")
	}
	xhook_uri, _ := url.Parse(os.Getenv("XHOOK_URL"))
	if xhook_uri.String() != "" {
		uri = xhook_uri.String()
	}
	slog.Info("[SYS] uri=[" + uri + "]")
}

func getToken() {
	dat, err := os.ReadFile(os.Getenv("HOME") + "/.xhookcontrol/.token")
	if err != nil {
		slog.Error(err.Error())
	} else {
		token = string(dat)
	}
	if len(token) == 0 {
		slog.Error("[AUTH] token unset")
	} else {
		slog.Debug("[AUTH]", "token", token)
	}
}

func getAuthInfo() error {
	if len(token) > 0 {
		slog.Debug("[AUTH]", "token", token)

		method := "GET"
		client := &http.Client{}
		req, err := http.NewRequest(method, uri+"/auth/profile", nil)
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+token)

		res, err := client.Do(req)
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			slog.Error(err.Error())
		} else {
			slog.Debug("[AUTH]", "body", body)
			if res.StatusCode == 200 {
				err := json.Unmarshal(body, &auth_info)
				if err != nil {
					slog.Error("[AUTH] " + err.Error())
					return nil
				} else {
					slog.Info("[AUTH] Profile, Email: " + auth_info.User.Email + ", Org=" + auth_info.User.Organisation +
						", Default_Project=" + auth_info.User.Options.Proj +
						", Status=" + strconv.FormatBool(auth_info.Status))
					org = auth_info.User.Organisation
					if len(auth_info.User.Options.Proj) > 0 {
						proj = auth_info.User.Options.Proj
					}
				}
			} else if res.StatusCode == 401 {
				slog.Info("[WORKFLOW] Unauthorized")
			} else {
				slog.Info("[WORKFLOW] not found rc=[" + strconv.Itoa(res.StatusCode) + "]")
			}
		}
	} else {
		slog.Info("[AUTH] token unset")
	}
	return nil
}

func access_show_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("show")
	getToken()
	if len(token) > 0 {
		slog.Info("[AUTH]", "token", token)
	}
	return nil
}

func access_generate_do(cCtx *cli.Context) error {
	cCtx.Command.FullName()
	cCtx.Command.HasName("access")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()
	reader := bufio.NewReader(os.Stdin)

	os.Mkdir(os.Getenv("HOME")+"/.xhookcontrol/", os.ModePerm)

	method := "POST"

	if cCtx.String("user") == "" {
		fmt.Print("User/email: ")
		user_input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println(err)
		} else {
			user = strings.TrimSpace(user_input)
		}
	}
	if cCtx.String("password") == "" {
		fmt.Print("Password: ")
		password_input, err := go_asterisks.GetUsersPassword("", true, os.Stdin, os.Stdout)
		if err != nil {
			panic(err)
		} else {
			password = strings.TrimSpace(string(password_input))
		}
	}
	payload = fmt.Sprintf("{\"email\":\"%s\",\"password\":\"%s\"}", user, password)
	slog.Debug("[AUTH]", "body", payload)

	client := &http.Client{}
	req, err := http.NewRequest(method, uri+"/auth/token", strings.NewReader(payload))
	if err != nil {
		log.Fatalln(err)
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	// req.Header.Add("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjp7ImlkIjoxLCJlbWFpbCI6Inhob29rX2FkbWluQGVzZGF0YS5jbyIsInJvbGUiOiJBZG1pbiJ9LCJpYXQiOjE2NjQ2MDc3ODksImV4cCI6MTY5NjE0Mzc4OX0.qaOZwxRqdeN6S4gahS6wK9pPYRrB8F024XCEi5jLrdw")

	res, err := client.Do(req)
	if err != nil {
		log.Fatalln(err)
		return err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	slog.Debug("[HTTP]" + http.StatusText(res.StatusCode))
	if err != nil {
		log.Fatalln(err)
		return err
	} else {
		if res.StatusCode == 200 {
			v := struct {
				Token string `json:"token"`
			}{}
			result, err := marshmallow.Unmarshal(body, &v)
			if err != nil {
				slog.Debug("[SYS] ", "token", result)
				log.Fatalln(err)
				return nil
			}
			err = os.WriteFile(os.Getenv("HOME")+"/.xhookcontrol/.token", []byte(v.Token), 0644)
			if err != nil {
				panic(err)
			} else {
				slog.Debug("[AUTH]", "token", result)
				slog.Info("[AUTH] Token saved under ~/.xhookcontrol/.token")
			}
		} else {
			slog.Info("[AUTH] Invalid respond")
		}
	}

	return nil
}

func access_revoke_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("revoke")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()

	dat, err := os.ReadFile(os.Getenv("HOME") + "/.xhookcontrol/.token")
	if err != nil {
		slog.Error(err.Error())
	} else {
		token = string(dat)
	}

	if len(token) == 0 {
		slog.Error("[AUTH] token unset")
	} else {
		slog.Debug("[AUTH] token revoked.", "token", token)

		method := "POST"
		client := &http.Client{}
		req, err := http.NewRequest(method, uri+"/auth/token/revoke", strings.NewReader("{\"user_id\": 1}"))
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+token)

		res, err := client.Do(req)
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			slog.Error(err.Error())
		} else {
			slog.Debug("[AUTH] token revoked.", "body", body)
			v := struct {
				Status  string `json:"status"`
				Auth    string `json:"auth"`
				Message string `json:"message"`
			}{}
			marshmallow.Unmarshal(body, &v)
			if res.StatusCode == 200 {
				slog.Info("[AUTH] token revoked.")
			} else {
				slog.Info("[AUTH] token not revoked.", "message", v.Message, "status", v.Status)
			}
		}
	}

	return nil
}

func access_info_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("access")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()

	getAuthInfo()

	return nil
}

func json_print_array_tables(hdr []string, class interface{}) {
	if jsonData, ok := class.([]Workflow); ok {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(hdr)
		for j := 0; j < len(jsonData); j++ {
			table.Append([]string{color.BlueString(jsonData[j].Name),
				jsonData[j].Summary,
				jsonData[j].Publish,
				strings.Join(jsonData[j].Tags, ",")})
		}
		table.SetFooter([]string{fmt.Sprint(len(jsonData)), "", "", " "})
		table.SetAutoMergeCells(true)
		table.Render()
	}
}

func createKeyValuePairs(m map[string]json.RawMessage) string {
	b := new(bytes.Buffer)
	for key, value := range m {
		fmt.Fprintf(b, "%s=\"%s\"\n", key, value)
	}
	return b.String()
}

func structToMap(obj interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	val := reflect.ValueOf(obj)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}
	typ := val.Type()
	fmt.Println(typ)

	for i := 0; i < val.NumField(); i++ {
		fieldName := typ.Field(i).Name
		fieldValueKind := val.Field(i).Kind()
		var fieldValue interface{}
		if fieldValueKind == reflect.Struct {
			fieldValue = structToMap(val.Field(i).Interface())
		} else {
			fieldValue = val.Field(i).Interface()
		}
		result[fieldName] = fieldValue
	}
	return result
}

func json_print_tables(class interface{}) {
	table := tablewriter.NewWriter(os.Stdout)
	values := reflect.ValueOf(class)
	types := values.Type()
	for i := 0; i < values.NumField(); i++ {
		// fmt.Println(types.Field(i).Type, values.Field(i))
		switch {
		case types.Field(i).Type == reflect.TypeOf(int(0)): // int
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		case types.Field(i).Type == reflect.TypeOf(""):
			table.Append([]string{color.BlueString(types.Field(i).Name), values.Field(i).String()})
		case types.Field(i).Type == reflect.TypeOf([]string{}):
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		case types.Field(i).Type.Kind() == reflect.Map:
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		}
	}
	table.Render()
}

func write_file(file_output string, body string) {
	f, err := os.Create(file_output)
	if err != nil {
		slog.Error("[WORKFLOW] " + err.Error())
		return
	}
	l, err := f.WriteString(string(body))
	if err != nil {
		slog.Error("[WORKFLOW] " + err.Error())
		f.Close()
		return
	} else {
		fmt.Println(color.BlueString("Output file: " + file_output + ", Size: " + strconv.Itoa(l)))
	}
	err = f.Close()
	if err != nil {
		slog.Error("[WORKFLOW] " + err.Error())
		return
	}
}

func workflow_list_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("workflow")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()

	// AUTH
	if len(token) == 0 {
		slog.Error("[AUTH] no access")
		exitCode = 401
		return nil
	}

	// REQ - workflows
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, uri+"/workflows/"+workflow_name, nil)
	if err != nil {
		slog.Error(err.Error())
		return err
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Bearer "+token)
	res, err := client.Do(req)
	if err != nil {
		slog.Error(err.Error())
		return err
	}
	defer res.Body.Close()

	// Parse Body
	body, err := io.ReadAll(res.Body)
	if err != nil {
		slog.Error(err.Error())
	} else {
		if res.StatusCode == 200 {
			slog.Debug("Body: " + string(body))
			if body[0] == '[' {
				err := json.Unmarshal(body, &workflows)
				if err != nil {
					slog.Error("[WORKFLOW] " + err.Error())
					slog.Error(color.RedString("[WORKFLOW] not found rc=[" + strconv.Itoa(res.StatusCode) + "]"))
					return nil
				} else {
					fmt.Println(color.RedString("<<WORKFLOWS>>"))
					if len(file_output) > 0 {
						write_file(file_output, string(body))
					} else if json_format {
						j, _ := json.MarshalIndent(string(body), "", "  ")
						fmt.Println(string(j))
					} else {
						json_print_array_tables([]string{"name", "summary", "publish", "tags"}, workflows)
					}
				}
			} else {
				err := json.Unmarshal(body, &workflow)
				if err != nil {
					slog.Error("[WORKFLOW] " + err.Error())
					slog.Error("[WORKFLOW] not found rc=[" + strconv.Itoa(res.StatusCode) + "]")
					return nil
				} else {
					fmt.Println(color.RedString("<<WORKFLOWS>> " + workflow.Name))
					json_print_tables(workflow)
				}
			}
		} else if res.StatusCode == 401 {
			slog.Info("[WORKFLOW] Unauthorized")
			exitCode = 401
		} else {
			slog.Error(color.RedString("[WORKFLOW] not found rc=[" + strconv.Itoa(res.StatusCode) + "]"))
		}
	}
	return nil
}

func workflow_run_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("workflow")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()

	// AUTH
	if len(token) == 0 {
		slog.Error("[AUTH] no access")
		exitCode = 401
		return nil
	}

	if workflow_name != "" {
		slog.Info("[WORKFLOW] NAME: " + color.BlueString(workflow_name))
		if len(workflow_parameters) > 0 {
			slog.Info("[WORKFLOW] run", "parameters", workflow_parameters)
		}
		method := "POST"
		client := &http.Client{}
		url_debug := ""
		if loglevel == "debug" {
			url_debug = "?loglevel=debug"
		}

		var payload = []byte(`{"parameters":{` + workflow_parameters + `}}`)
		slog.Debug("[WORKFLOW]", "payload", payload)
		req, err := http.NewRequest(method, uri+"/workflows/run/"+workflow_name+url_debug, bytes.NewBuffer(payload))
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Authorization", "Bearer "+token)

		res, err := client.Do(req)
		if err != nil {
			slog.Error(err.Error())
			return err
		}
		defer res.Body.Close()

		body, err := io.ReadAll(res.Body)
		if err != nil {
			slog.Error(err.Error())
		} else {
			err := json.Unmarshal(body, &workflow_run)
			if err != nil {
				slog.Error("[WORKFLOW] " + err.Error())
				return nil
			}
			if res.StatusCode == 200 {
				// Workflow result
				var headerKey []string
				slog.Info("[WORKFLOW] " + "RUN_ID: " + color.BlueString(workflow_run.Id))
				fmt.Println(color.RedString("<<RESULTS>>"))
				for k := range workflow_run.Result {
					table := tablewriter.NewWriter(os.Stdout)
					jsonDtlRaw := make(map[string]json.RawMessage)
					err := json.Unmarshal(workflow_run.Result[k], &jsonDtlRaw)
					if err != nil { // JSON Array
						/// slog.Error("[WORKFLOW] " + err.Error())
						jsonDtl := make([]map[string]string, len(jsonDtlRaw))
						err = json.Unmarshal(workflow_run.Result[k], &jsonDtl)
						if err != nil {
							slog.Error("[WORKFLOW] " + err.Error())
						} else {
							// fmt.Println(string(workflow_run.Result[k]))
							fmt.Println("* " + color.BlueString(k+": "+fmt.Sprint(len(jsonDtl))))
							for k1 := range jsonDtl {
								var headerDtl []string
								for k2 := range jsonDtl[k1] {
									if !slices.Contains(headerKey, k2) {
										headerKey = append(headerKey, k2)
									}
									headerDtl = append(headerDtl, jsonDtl[k1][k2])
								}
								table.Append(headerDtl)
							}
							if len(headerKey) > 0 {
								table.SetHeader(headerKey)
								// fmt.Println("* Count: " + color.BlueString(fmt.Sprint(len(workflow_run.Result[k]))))
								table.Render()
							} else {
								fmt.Println("* No results")
							}
						}
					} else { // raw data
						fmt.Println("* " + color.BlueString(k+": "+fmt.Sprint(len(jsonDtlRaw))))
						for jsonFld, _ := range jsonDtlRaw {
							table.Append([]string{color.BlueString(jsonFld), string(jsonDtlRaw[jsonFld])})
						}
						table.SetHeader(headerKey)
						table.Render()
					}
				}
				slog.Debug("[WORKFLOW] " + string(body))
				slog.Info(color.BlueString(workflow_run.Message))
			} else if res.StatusCode == 401 {
				slog.Error(color.RedString("[WORKFLOW] ") + "Unauthorized")
				slog.Error(color.RedString("[WORKFLOW] " + workflow_run.Message))
				exitCode = 1
			} else if res.StatusCode == 500 {
				// slog.Info("[WORKFLOW] Invalid parameters format, verify arguments")
				err := json.Unmarshal(body, &workflow_run)
				if err != nil {
					slog.Error(color.RedString("[WORKFLOW] ") + err.Error())
				} else {
					slog.Error(color.RedString("[WORKFLOW] ") + string(body))
				}
				slog.Error(color.RedString(workflow_run.Message))
				exitCode = 1
			} else {
				slog.Error("[WORKFLOW] run rc=[" + strconv.Itoa(res.StatusCode) + "]")
				slog.Error(color.RedString("[WORKFLOW] " + workflow_run.Message))
				exitCode = 1
			}
		}
	} else {
		slog.Error(color.RedString("[WORKFLOW] name not provided"))
		exitCode = 1
	}
	return nil
}

func buildAppInstance() (appInst *cli.App) {
	appInst = &cli.App{
		Name:     "xhook-cli",
		Version:  banner.Version,
		Compiled: time.Now(),
		Authors: []*cli.Author{
			{
				Name:  "esData",
				Email: "support@esdata.co",
			},
		},
		Copyright: "(c)2025 esData",
		Usage:     "xHook control command line interface",
		UsageText: "xHook control [command] [options]",
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "access",
				Usage:       "Manage access credentials and project profile",
				UsageText:   "access [options]",
				Description: "Manage access credentials, by default, ~/.xhookcontrol/.credentials",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name:  "generate",
						Usage: "Generate token",
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "user",
								Aliases:     []string{"u"},
								Usage:       "User/email",
								Destination: &user,
							},
							&cli.StringFlag{
								Name:        "password",
								Aliases:     []string{"p"},
								Usage:       "Password [optional]",
								Destination: &password,
							},
							&cli.StringFlag{
								Name:        "token",
								Aliases:     []string{"t"},
								Usage:       "Token",
								Destination: &token,
							},
							&cli.StringFlag{
								Name:        "lifetime",
								Usage:       "Token lifetime",
								Value:       "1h",
								Destination: &lifetime,
							},
							&cli.StringFlag{
								Name:        "project",
								Value:       "undef_proj",
								Destination: &proj,
							},
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
						Action: access_generate_do,
					},
					&cli.Command{
						Name:   "show",
						Usage:  "Display token metadata",
						Action: access_show_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
					},
					&cli.Command{
						Name:   "info",
						Usage:  "Display profile info",
						Action: access_info_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
					},
					&cli.Command{
						Name:   "revoke",
						Usage:  "Revoke token",
						Action: access_revoke_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
					},
				},
				SkipFlagParsing: false,
				HideHelp:        false,
				Hidden:          false,
			},
			&cli.Command{
				Name:        "workflow",
				Usage:       "Workflow command",
				UsageText:   "Workflow [command] [options]",
				Description: "Workflow operation",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name:   "list",
						Usage:  "Workflow list",
						Action: workflow_list_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "name",
								Aliases:     []string{"w"},
								Usage:       "Workflow name",
								Destination: &workflow_name,
							},
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
							&cli.BoolFlag{
								Name:        "json",
								Value:       false,
								Usage:       "json format",
								Destination: &json_format,
							},
							&cli.StringFlag{
								Name:        "output",
								Aliases:     []string{"o"},
								Usage:       "Output json format to file",
								Destination: &file_output,
							},
						},
					},
					&cli.Command{
						Name:      "run",
						Usage:     "Workflow run",
						UsageText: "Workflow run --[name/id]",
						Action:    workflow_run_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "name",
								Aliases:     []string{"w"},
								Usage:       "Workflow name",
								Destination: &workflow_name,
							},
							&cli.StringFlag{
								Name:        "parameters",
								Aliases:     []string{"p"},
								Usage:       "Workflow parameters in Yaml (key:value)",
								Destination: &workflow_parameters,
							},
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
					},
					&cli.Command{
						Name:  "logs",
						Usage: "Workflow logs",
						// Action: workflow_logs_do,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "name",
								Aliases:     []string{"w"},
								Usage:       "Workflow name",
								Destination: &workflow_name,
							},
							&cli.StringFlag{
								Name:        "uri",
								Aliases:     []string{"s"},
								Value:       "https://xhook-api.esdata.io:8443",
								Usage:       "uri end-point",
								Destination: &uri,
							},
							&cli.StringFlag{
								Name:        "loglevel",
								Aliases:     []string{"l"},
								Value:       "info",
								Usage:       "loglevel",
								Destination: &loglevel,
							},
						},
					},
				},
				SkipFlagParsing: false,
				HideHelp:        false,
				Hidden:          false,
				// Action:          access_do,
				// OnUsageError: func(cCtx *cli.Context, err error, isSubcommand bool) error {
				//	slog.Error("Invalid flags")
				//	return err
				// },
			},
		},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "uri",
				Aliases:     []string{"s"},
				Value:       "https://xhook-api.esdata.io:8443",
				Usage:       "uri end-point",
				Destination: &uri,
			},
			&cli.StringFlag{
				Name:        "loglevel",
				Aliases:     []string{"l"},
				Value:       "info",
				Usage:       "loglevel",
				Destination: &loglevel,
			},
		},
		EnableBashCompletion: true,
	}
	return appInst
}

func init() {
	log.SetFlags(log.Ldate | log.Lmicroseconds)
	banner.PrintRev()
	getToken()
}

func main() {
	app := buildAppInstance()
	app.Run(os.Args)
	os.Exit(exitCode)
}
