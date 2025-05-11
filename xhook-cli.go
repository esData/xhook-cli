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
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"esdata.co/xhook-control/xhook-cli/banner"
	"github.com/briandowns/spinner"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/perimeterx/marshmallow"
	"github.com/urfave/cli/v2"
	"gitlab.com/david_mbuvi/go_asterisks"
)

const Uri = "https://xhook-api.esdata.io:8443"
const Org = "unset_org"
const Proj = "undef_proj"
const listHeight = 14
const defaultWidth = 20
const test_internet_ip = "8.8.8.8:53"

type item string

func (i item) FilterValue() string { return "" }

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }
func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	i, ok := listItem.(item)
	if !ok {
		return
	}

	str := fmt.Sprintf("%d. %s", index+1, i)

	fn := itemStyle.Render
	if index == m.Index() {
		fn = func(s ...string) string {
			return selectedItemStyle.Render("> " + strings.Join(s, " "))
		}
	}

	fmt.Fprint(w, fn(str))
}

type model struct {
	list     list.Model
	choice   string
	quitting bool
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.list.SetWidth(msg.Width)
		return m, nil

	case tea.KeyMsg:
		switch keypress := msg.String(); keypress {
		case "q", "ctrl+c":
			m.quitting = true
			return m, tea.Quit

		case "enter":
			i, ok := m.list.SelectedItem().(item)
			if ok {
				m.choice = string(i)
			}
			return m, tea.Quit
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m model) View() string {
	if m.choice != "" {
		return quitTextStyle.Render(fmt.Sprintf("%s? Sounds good to me.", m.choice))
	}
	if m.quitting {
		return quitTextStyle.Render("Not hungry? That’s cool.")
	}
	return "\n" + m.list.View()
}

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
	Name       string
	Summary    string
	Publish    string
	Tags       []string
	Parameters json.RawMessage
	// Steps       json.RawMessage
	Trigger     json.RawMessage
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

type Workflow_run_logs struct {
	Run_id     string
	UpdatedAt  time.Time
	Duration   int
	Status     string
	Outputs    string
	Parameters map[string]json.RawMessage `json:"parameters,omitempty"`
	Results    map[string]json.RawMessage `json:"results,omitempty"`
	Message    []string
}

type Payload struct {
	Workflow_name string
	Email         string
	Publish       string
	Tags          []string
	Parameters    json.RawMessage
	Description   string
	UpdatedAt     time.Time
}

type Payload_detail struct {
	Run_id        string
	Workflow_name string
	Payload_name  string
	Payload_type  string
	Payload       string
	Payload_md5   string
	Email         string
	Publish       string
	UpdatedAt     time.Time
}

var (
	user     = ""
	password = ""

	auth_info Auth_Info
	org       = Org
	proj      = Proj

	token               = ""
	lifetime            = ""
	loglevel            = "info"
	payload             = ""
	workflow_name       = ""
	workflow_parameters = ""
	workflow            Workflow
	workflows           []Workflow
	workflow_run        Workflow_run
	workflow_run_logs   []Workflow_run_logs
	workflow_file       = ""
	uri                 = Uri
	exitCode            = 0
	json_format         = false
	file_output         = ""
	workflow_run_id     = ""
	xrp_spec_run        = false
	payloads            []Payload
	payload_details     []Payload_detail
	use_selector        = false
	has_internet        = true

	titleStyle        = lipgloss.NewStyle().MarginLeft(2)
	itemStyle         = lipgloss.NewStyle().PaddingLeft(4)
	selectedItemStyle = lipgloss.NewStyle().PaddingLeft(2).Foreground(lipgloss.Color("170"))
	paginationStyle   = list.DefaultStyles().PaginationStyle.PaddingLeft(4)
	helpStyle         = list.DefaultStyles().HelpStyle.PaddingLeft(4).PaddingBottom(1)
	quitTextStyle     = lipgloss.NewStyle().Margin(1, 0, 2, 4)
)

func hasInternetConnection() bool {
	_, err := net.DialTimeout("tcp", test_internet_ip, 3*time.Second)
	return err == nil
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
								Value:       "",
								Usage:       "Workflow name",
								Destination: &workflow_name,
							},
							&cli.StringFlag{
								Name:        "payload",
								Aliases:     []string{"c"},
								Value:       "",
								Usage:       "payload in json/yaml",
								Destination: &payload,
							},
							&cli.StringFlag{
								Name:        "workflow_file",
								Aliases:     []string{"f"},
								Value:       "",
								Usage:       "Workflow file",
								Destination: &workflow_file,
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
							&cli.BoolFlag{
								Name:        "xrpspec",
								Usage:       "XRPSpec test",
								Destination: &xrp_spec_run,
							},
							&cli.BoolFlag{
								Name:        "selector",
								Value:       false,
								Usage:       "Use selector",
								Destination: &use_selector,
							},
							&cli.BoolFlag{
								Name:        "json",
								Usage:       "json format",
								Destination: &json_format,
							},
						},
					},
					&cli.Command{
						Name:      "logs",
						Usage:     "Workflow logs",
						UsageText: "Workflow logs --name",
						Action:    workflow_run_log,
						Flags: []cli.Flag{
							&cli.StringFlag{
								Name:        "name",
								Aliases:     []string{"w"},
								Usage:       "Workflow name",
								Destination: &workflow_name,
							},
							&cli.StringFlag{
								Name:        "run_id",
								Aliases:     []string{"i"},
								Usage:       "Workflow run id",
								Destination: &workflow_run_id,
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
				},
				SkipFlagParsing: false,
				HideHelp:        false,
				Hidden:          false,
			},
			&cli.Command{
				Name:        "payload",
				Usage:       "Payload command",
				UsageText:   "Payload [command] [options]",
				Description: "Payload operation",
				Subcommands: []*cli.Command{
					&cli.Command{
						Name:   "list",
						Usage:  "payload list",
						Action: payload_list_do,
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
							&cli.StringFlag{
								Name:        "output_path",
								Aliases:     []string{"o"},
								Usage:       "Output payloads to directory",
								Destination: &file_output,
							},
						},
					},
				},
				SkipFlagParsing: false,
				HideHelp:        false,
				Hidden:          false,
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
	has_internet = hasInternetConnection()
	getToken()
	banner.PrintRev()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		slog.Error("[SYS] Error getting network interfaces:" + err.Error())
		os.Exit(1)
	}
	ip_i := 0
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				if ip_i == 0 {
					fmt.Print("  Network:\n    IP address: ", ipnet.IP.String())
					ip_i++
				} else {
					fmt.Print(", ", ipnet.IP.String())
				}
			}
		}
	}
	fmt.Printf("\n    Internet connection: %t\n\n", has_internet)
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
	if uri != Uri {
		slog.Info("[SYS] uri=[" + uri + "]")
	}
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
	} else if jsonData, ok := class.([]Payload); ok {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(hdr)
		for j := 0; j < len(jsonData); j++ {
			jsonDataParams, _ := json.Marshal(&jsonData[j].Parameters)
			re := regexp.MustCompile(`,"`)
			table.Append([]string{color.BlueString(jsonData[j].Workflow_name),
				jsonData[j].UpdatedAt.String(),
				re.ReplaceAllString(string(jsonDataParams), ",\n\""),
			})
		}
		table.SetFooter([]string{fmt.Sprint(len(jsonData)), "", " "})
		table.SetAutoMergeCells(true)
		table.SetAutoWrapText(true)
		table.Render()
	} else if jsonData, ok := class.([]Payload_detail); ok {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(hdr)
		for j := 0; j < len(jsonData); j++ {
			table.Append([]string{color.BlueString(jsonData[j].Run_id),
				jsonData[j].Workflow_name,
				jsonData[j].Payload_name,
				jsonData[j].Payload_type,
			})
			if len(file_output) > 0 && jsonData[j].Payload_type == "source_code" {
				write_file(file_output+"/"+jsonData[j].Payload_name, jsonData[j].Payload)
			}
		}
		table.SetFooter([]string{fmt.Sprint(len(jsonData)), "", "", " "})
		table.SetAutoMergeCells(true)
		table.SetAutoWrapText(true)
		table.Render()
	}
}

func json_print_tables(class interface{}) {
	table := tablewriter.NewWriter(os.Stdout)
	values := reflect.ValueOf(class)
	types := values.Type()
	for i := 0; i < values.NumField(); i++ {
		switch {
		case types.Field(i).Type == reflect.TypeOf(int(0)): // int
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		case types.Field(i).Type == reflect.TypeOf(""):
			table.Append([]string{color.BlueString(types.Field(i).Name), values.Field(i).String()})
		case types.Field(i).Type == reflect.TypeOf([]string{}):
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		case types.Field(i).Type.Kind() == reflect.Map:
			table.Append([]string{color.BlueString(types.Field(i).Name), fmt.Sprintf("%s", values.Field(i))})
		case types.Field(i).Type == reflect.TypeOf(json.RawMessage{}):
			jsonFldData, _ := json.Marshal(json.RawMessage(values.Field(i).Bytes()))
			re := regexp.MustCompile(`,"`)
			table.Append([]string{color.BlueString(types.Field(i).Name),
				re.ReplaceAllString(string(jsonFldData), ",\n\"")})
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

	g := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	g.Start()
	g.Prefix = "Getting workflow list..."
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
	g.Stop()

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

	if workflow_name == "" && payload == "" && workflow_file == "" {
		slog.Error(color.RedString("[WORKFLOW] name/payload not provided"))
		exitCode = 1
		return nil
	}

	slog.Info("[WORKFLOW] NAME: " + color.BlueString(workflow_name))
	if len(workflow_parameters) > 0 {
		slog.Info("[WORKFLOW] run", "parameters", workflow_parameters)
	}
	method := "POST"
	client := &http.Client{}
	url_debug := ""
	xrp_spec_run_enabled := ""
	if loglevel == "debug" {
		url_debug = "?loglevel=debug"
	}
	if xrp_spec_run {
		xrp_spec_run_enabled = "/xspec"
	}

	var http_payload = []byte(`{"parameters":{` + workflow_parameters + `}}`)
	if payload != "" {
		http_payload = []byte(payload)
	}
	if workflow_file != "" {
		http_payload, _ = os.ReadFile(workflow_file)
	}
	g := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
	g.Start()
	g.Prefix = "Invoke workflow..."
	slog.Debug("[WORKFLOW]", "payload", http_payload)
	req, err := http.NewRequest(method, uri+"/workflows/run/"+workflow_name+xrp_spec_run_enabled+url_debug, bytes.NewBuffer(http_payload))
	if err != nil {
		slog.Error(err.Error())
		return err
	}
	if http_payload[0] == '{' {
		req.Header.Add("Content-Type", "application/json")
	} else {
		req.Header.Add("Content-Type", "application/x-yaml")
	}
	req.Header.Add("Authorization", "Bearer "+token)

	res, err := client.Do(req)
	if err != nil {
		slog.Error(err.Error())
		return err
	}
	defer res.Body.Close()
	g.Stop()

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
			if json_format {
				j, _ := json.MarshalIndent(string(body), "", "  ")
				fmt.Println(string(j))
			} else {
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
							if use_selector {
								items := []list.Item{}
								for k1 := range jsonDtl {
									for k2 := range jsonDtl[k1] {
										if k2 == "mac" {
											items = append(items, item(jsonDtl[k1][k2]))
										}
									}
								}
								l := list.New(items, itemDelegate{}, defaultWidth, listHeight)
								l.Title = "Select an itme for your next actions"
								l.SetShowStatusBar(false)
								l.SetFilteringEnabled(false)
								l.Styles.Title = titleStyle
								l.Styles.PaginationStyle = paginationStyle
								l.Styles.HelpStyle = helpStyle

								m := model{list: l}
								if _, err := tea.NewProgram(m).Run(); err != nil {
									fmt.Println("Error running program:", err)
									os.Exit(1)
								}
							} else {
								// slice.Sort(jsonDtl[:], func(i, j int) bool {}}
								for k1 := range jsonDtl {
									var headerDtl []string
									if len(headerKey) == 0 {
										for k2 := range jsonDtl[k1] {
											if !slices.Contains(headerKey, k2) {
												headerKey = append(headerKey, k2)
											}
										}
									}
									for _, k2 := range headerKey {
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
	return nil
}

func workflow_run_log(cCtx *cli.Context) error {
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

	if workflow_run_id != "" {
		slog.Info("[WORKFLOW] Run id" + workflow_run_id)
		method := "GET"
		client := &http.Client{}
		req, err := http.NewRequest(method, uri+"/workflows/run/"+workflow_run_id, nil)
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
			err := json.Unmarshal(body, &workflow_run_logs)
			if err != nil {
				slog.Error("[WORKFLOW] " + err.Error())
				return nil
			}
			if res.StatusCode == 200 {
				table := tablewriter.NewWriter(os.Stdout)
				for k := range workflow_run_logs {
					if workflow_run_logs[k].Status == "error" {
						table.Append([]string{"Status", color.RedString(workflow_run_logs[k].Status)})
					} else {
						table.Append([]string{"Status", color.BlueString(workflow_run_logs[k].Status)})
					}
					table.Append([]string{"Date", workflow_run_logs[k].UpdatedAt.String()})
					table.Append([]string{"Duration(s)", strconv.Itoa(workflow_run_logs[k].Duration)})
					table.Append([]string{"Message", strings.Join(workflow_run_logs[k].Message, ",")})
					table.Append([]string{"Outputs", workflow_run_logs[k].Outputs})
				}
				table.Render()
				slog.Debug("[WORKFLOW] " + string(body))
				if len(file_output) > 0 {
					write_file(file_output, string(body))
				} else if json_format {
					j, _ := json.MarshalIndent(string(body), "", "  ")
					fmt.Println(string(j))
				}
			} else if res.StatusCode == 401 {
				slog.Error(color.RedString("[WORKFLOW] ") + "Unauthorized")
				exitCode = 1
			}
		}
	} else if workflow_name != "" {
		slog.Info("[WORKFLOW] NAME: " + color.BlueString(workflow_name))

		method := "GET"
		client := &http.Client{}
		req, err := http.NewRequest(method, uri+"/workflows/run/"+workflow_name, nil)
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
			err := json.Unmarshal(body, &workflow_run_logs)
			if err != nil {
				slog.Error("[WORKFLOW] " + err.Error())
				return nil
			}
			if res.StatusCode == 200 {
				// TODO: use common print_array_tables
				// Workflow result
				// var headerKey []string
				// fmt.Println(color.RedString("<<RESULTS>>"))
				// json_print_array_tables([]string{"Run ID", "Date", "Duration", "Status"}, workflow_run_logs)
				table := tablewriter.NewWriter(os.Stdout)
				table.Append([]string{"Run ID", "Date", "Duration", "Status"})
				for k := range workflow_run_logs {
					if workflow_run_logs[k].Status == "error" {
						table.Append([]string{color.RedString(workflow_run_logs[k].Run_id),
							workflow_run_logs[k].UpdatedAt.String(),
							strconv.Itoa(workflow_run_logs[k].Duration),
							workflow_run_logs[k].Status})
					} else {
						table.Append([]string{color.BlueString(workflow_run_logs[k].Run_id),
							workflow_run_logs[k].UpdatedAt.String(),
							strconv.Itoa(workflow_run_logs[k].Duration),
							workflow_run_logs[k].Status})
					}
				}
				table.SetFooter([]string{fmt.Sprint(len(workflow_run_logs)), "", "", " "})
				table.Render()
				slog.Debug("[WORKFLOW] " + string(body))
			} else if res.StatusCode == 401 {
				slog.Error(color.RedString("[WORKFLOW] ") + "Unauthorized")
				exitCode = 1
			}
		}
	} else {
		slog.Error(color.RedString("[WORKFLOW] name not provided"))
		exitCode = 1
	}
	return nil
}

func payload_list_do(cCtx *cli.Context) error {
	setParams()
	cCtx.Command.FullName()
	cCtx.Command.HasName("payload")
	cCtx.Command.Names()
	cCtx.Command.VisibleFlags()

	// AUTH
	if len(token) == 0 {
		slog.Error("[AUTH] no access")
		exitCode = 401
		return nil
	}

	// REQ - Payload
	method := "GET"
	client := &http.Client{}
	req, err := http.NewRequest(method, uri+"/payloads/"+workflow_name, nil)
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
			fmt.Println(color.RedString("<<PAYLOADS>>") + " " + workflow_name)
			if body[0] == '[' && body[1] != ']' {
				if len(workflow_name) > 0 {
					err := json.Unmarshal(body, &payload_details)
					if err != nil {
						slog.Error("[PAYLOAD] " + err.Error())
						slog.Error(color.RedString("[PAYLOAD] not found rc=[" + strconv.Itoa(res.StatusCode) + "]"))
						return nil
					}
				} else {
					err := json.Unmarshal(body, &payloads)
					if err != nil {
						slog.Error("[PAYLOAD] " + err.Error())
						slog.Error(color.RedString("[PAYLOAD] not found rc=[" + strconv.Itoa(res.StatusCode) + "]"))
						return nil
					}
				}
				if len(workflow_name) > 0 {
					json_print_array_tables([]string{"run_id", "name", "payload_name", "type"}, payload_details)
				} else {
					json_print_array_tables([]string{"name", "date", "parameters"}, payloads)
				}
			} else if body[0] == '[' && body[1] == ']' {
				slog.Error(color.RedString("[PAYLOAD] not found"))
			} else {
				err := json.Unmarshal(body, &payloads)
				fmt.Println(color.RedString("<<PAYLOADS>> " + workflow_name))
				if err != nil {
					slog.Error("[PAYLOAD] " + err.Error())
					slog.Error("[PAYLOAD] not found rc=[" + strconv.Itoa(res.StatusCode) + "]")
					return nil
				} else {
					json_print_tables(payloads)
				}
			}
		} else if res.StatusCode == 401 {
			slog.Info("[PAYLOAD] Unauthorized")
			exitCode = 401
		} else {
			slog.Error(color.RedString("[PAYLOAD] not found rc=[" + strconv.Itoa(res.StatusCode) + "]"))
		}
	}
	return nil
}

func main() {
	app := buildAppInstance()
	app.Run(os.Args)
	os.Exit(exitCode)
}
