package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/mitchellh/mapstructure"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// Re-using the app struct from rverton (webanalyze) - thanks
// https://github.com/rverton/webanalyze/blob/master/wappalyze.go

// StringArray type is a wrapper for []string for use in unmarshalling the technologies.json
type StringArray []string

// App type encapsulates all the data about an App from technologies.json
type App struct {
	Cats     []int                  `json:"cats"`
	CatNames []string               `json:"category_names"`
	Cookies  map[string]string      `json:"cookies"`
	Headers  map[string]string      `json:"headers"`
	Meta     map[string]StringArray `json:"meta"`
	HTML     StringArray            `json:"html"`
	Script   StringArray            `json:"script"`
	URL      StringArray            `json:"url"`
	Website  string                 `json:"website"`
	Implies  StringArray            `json:"implies"`
	// Adding Name (we're just parsing Wappalyzer)
	Name string `json:"name"`
}

type Matcher struct {
	Type         string        `yaml:"type,omitempty"`
	Name         string        `yaml:"name,omitempty"`
	Regex        []string      `yaml:"regex,omitempty"`
	Words        []string      `yaml:"words,omitempty"`
	Condition    string        `yaml:"condition,omitempty"`
	Part         string        `yaml:"part,omitempty"`
	Subtemplates []SubTemplate `yaml:"subtemplates,omitempty"`
}

type Request struct {
	Method            string    `yaml:"method"`
	Path              []string  `yaml:"path"`
	Redirects         bool      `yaml:"redirects"`
	MaxRedirects      int       `yaml:"max-redirects"`
	MatchersCondition string    `yaml:"matchers-condition"`
	Matchers          []Matcher `yaml:"matchers"`
}

type TemplateInfo struct {
	Name        string `yaml:"name,omitempty"`
	Author      string `yaml:"author,omitempty"`
	Description string `yaml:"description,omitempty"`
	Severity    string `yaml:"severity,omitempty"`
	Tags        string `yaml:"tags,omitempty"`
}

type TechDetect struct {
	ID       string       `yaml:"id"`
	Info     TemplateInfo `yaml:"info"`
	Requests []Request    `yaml:"requests"`
}

type Workflow struct {
	Template string    `yaml:"template"`
	Matchers []Matcher `yaml:"matchers"`
}

type SubTemplate struct {
	Tags []string `yaml:"tags"`
}

type WorkflowTemplate struct {
	ID        string       `yaml:"id"`
	Info      TemplateInfo `yaml:"info"`
	Workflows []Workflow   `yaml:"workflows"`
}

// exists returns whether the given file or directory exists
func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func trimLeftChars(s string, n int) string {
	m := 0
	for i := range s {
		if m >= n {
			return s[i:]
		}
		m++
	}
	return s[:0]
}

func processJson(results chan []App, path string) {
	log.Debugln("Reading JSON file", path)
	var dat map[string]interface{}
	var apps []App
	f, err := os.Open(path)
	if err != nil {
		log.Fatalf("Error opening JSON file %s: %s\n", path, err.Error())
	}
	defer f.Close()
	bytes, _ := ioutil.ReadAll(f)

	if err := json.Unmarshal(bytes, &dat); err != nil {
		log.Fatalf("Error unmarshalling JSON (%s): %s\n", path, err.Error())
	}
	for key, value := range dat {
		var app App
		mapstructure.Decode(value, &app)
		// Replace all spaces with dashes
		app.Name = strings.ReplaceAll(strings.ToLower(key), " ", "-")
		apps = append(apps, app)
	}
	results <- apps
}

func processListRegex(s StringArray) StringArray {
	var output StringArray
	for _, value := range s {
		// Strip version detection
		log.Traceln("processListRegex", value)
		output = append(output, strings.Split(value, "\\;")[0])
	}
	return output
}

func processMapRegex(d map[string]string) map[string]string {
	var output = make(map[string]string)
	for key, value := range d {
		// Strip version detection
		log.Traceln("processMapRegex", key, value)
		output[key] = strings.Split(value, "\\;")[0]
		// Remove the first char if it's a start of string regex
		if len(output[key]) > 0 && output[key][0] == '^' {
			output[key] = trimLeftChars(output[key], 1)
		}
	}
	return output
}

func DownloadFile(filepath string, url string) error {
	// Get the data
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Create the file
	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	// Write the body to file
	_, err = io.Copy(out, resp.Body)
	return err
}

func main() {
	forcePtr := flag.Bool("force", false, "Force re-clone of Wappalyzer repository")
	clonePathPtr := flag.String("clone-path", "./wappalyzer", "Path to clone Wappalyzer repository")
	debugPtr := flag.Bool("debug", false, "Set log level to debug")
	mergePtr := flag.Bool("merge-nuclei", false, "Download and merge non-overlapping matchers from nuclei's tech-detect.yaml")
	nucleiUrl := "https://raw.githubusercontent.com/projectdiscovery/nuclei-templates/master/technologies/tech-detect.yaml"
	flag.Parse()

	if *debugPtr {
		log.SetLevel(log.DebugLevel)
	}

	var wappalyzerFiles []string
	var apps []App
	var nucleiDetect TechDetect

	// Clone down the wappalyzer repo
	// https://github.com/AliasIO/wappalyzer
	if *forcePtr {
		if b, _ := exists(*clonePathPtr); b {
			log.Println("Removing Wappalyzer repo")
			os.RemoveAll(*clonePathPtr)
		} else {
			log.Warningf("%s doesn't seem to exist. Continuing.\n", *clonePathPtr)
		}
	}
	log.Println("Cloning Wappalyzer repo")
	_, err := git.PlainClone(*clonePathPtr, false, &git.CloneOptions{
		URL:      "https://github.com/AliasIO/wappalyzer",
		Progress: os.Stdout,
	})
	if err != nil {
		if !strings.Contains(err.Error(), "repository already exists") {
			log.Fatalln("Failed cloning the git repo:", err.Error())
		} else {
			log.Warningln("Repository already exists. Continuing.")
		}
	}

	if *mergePtr {
		log.Println("Downloading Nuclei's tech-detect.yaml")
		DownloadFile("./nuclei-tech-detect.yaml", nucleiUrl)
		d, err := ioutil.ReadFile("./nuclei-tech-detect.yaml")
		if err != nil {
			log.Fatalln("Error reading nuclei-tech-detect.yaml: ", err.Error())
		}
		err = yaml.Unmarshal(d, &nucleiDetect)
		if err != nil {
			log.Fatalln("Error unmarshalling nuclei-tech-detect.yaml: ", err.Error())
		}
	}

	err = filepath.Walk(filepath.Join(*clonePathPtr, "src", "technologies"), func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Errorln("Error while walking: ", err.Error())
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			wappalyzerFiles = append(wappalyzerFiles, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalln("Error walking directory: ", err.Error())
	}
	if len(wappalyzerFiles) == 0 {
		log.Fatalln("No technology JSON schemas found. Check your directory and try again.")
	}

	// Parse technologies/*.json, one go func per file
	// According to https://www.wappalyzer.com/docs/dev/specification/
	log.Printf("Found %d file(s) to process", len(wappalyzerFiles))
	results := make(chan []App, len(wappalyzerFiles))
	for _, path := range wappalyzerFiles {
		go processJson(results, path)
	}

	for i := 0; i < len(wappalyzerFiles); i++ {
		apps = append(apps, <-results...)
	}

	log.Printf("Found %d apps\n", len(apps))
	log.Println("Processing regexes")

	for index, app := range apps {
		// HTML, Script, and URL are just lists of regex
		apps[index].HTML = processListRegex(app.HTML)
		// We don't really need script or URL (can't use them in Nuclei)
		// Parse them anyway in case we need them
		apps[index].Script = processListRegex(app.Script)
		apps[index].URL = processListRegex(app.URL)
		// Headers and Cookies are maps
		apps[index].Headers = processMapRegex(app.Headers)
		apps[index].Cookies = processMapRegex(app.Cookies)
	}

	techDetect := TechDetect{
		ID: "nu-tech-detect",
		Info: TemplateInfo{
			Name:     "Wappalyzer Technology Detection",
			Author:   "jbertman",
			Severity: "info",
			Tags:     "tech",
		},
	}

	// We only need one request to the BaseURL
	baseRequest := Request{
		Method:            "GET",
		Path:              []string{"{{BaseURL}}"},
		Redirects:         true,
		MaxRedirects:      2,
		MatchersCondition: "or",
	}
	// Add the matchers
	matchers := []Matcher{}
	log.Println("Building matchers")
	for _, app := range apps {
		// HTML -> body regex
		if len(app.HTML) > 0 {
			matchers = append(matchers, Matcher{
				Type:      "regex",
				Name:      app.Name,
				Regex:     app.HTML,
				Condition: "or",
				Part:      "body",
			})
		}
		// Header -> header word (blank) or regex (val != "")
		if len(app.Headers) > 0 {
			// For anything that's blank, we'll get a list of keys (header words)
			words := []string{}
			// Otherwise it's a regex
			regexes := []string{}
			for k, v := range app.Headers {
				if len(v) > 0 {
					regexes = append(regexes, fmt.Sprintf("%s.*%s", k, v))
				} else {
					words = append(words, k)
				}
			}
			if len(words) > 0 {
				matchers = append(matchers, Matcher{
					Type:      "word",
					Name:      app.Name,
					Words:     words,
					Condition: "or",
					Part:      "header",
				})
			}
			if len(regexes) > 0 {
				matchers = append(matchers, Matcher{
					Type:      "regex",
					Name:      app.Name,
					Regex:     regexes,
					Condition: "or",
					Part:      "header",
				})
			}
		}
	}

	if *mergePtr {
		log.Println("Merging matchers from Nuclei")
		// Get all the existing matchers in a set (map)
		var m = make(map[string]int, len(matchers))
		var nucleiMatchers = []Matcher{}
		for _, matcher := range matchers {
			m[matcher.Name] = 1
		}
		// Loop through all the nuclei matchers
		// If we don't have it, add it to our slice
		for _, request := range nucleiDetect.Requests {
			for _, matcher := range request.Matchers {
				if _, ok := m[matcher.Name]; !ok {
					nucleiMatchers = append(nucleiMatchers, matcher)
				}
			}
		}
		if len(nucleiMatchers) > 0 {
			matchers = append(matchers, nucleiMatchers...)
			log.Printf("Merged %d non-overlapping matchers from Nuclei\n", len(nucleiMatchers))
		}
	}

	// Sort the matchers slice alpha by name
	log.Println("Sorting outputs")
	sort.Slice(matchers, func(i, j int) bool {
		return matchers[i].Name < matchers[j].Name
	})
	baseRequest.Matchers = matchers

	// Construct requests object
	requests := []Request{}
	requests = append(requests, baseRequest)
	techDetect.Requests = requests

	log.Println("Marshalling template")
	d, err := yaml.Marshal(&techDetect)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if b, _ := exists("nu-tech-detect.yaml"); b {
		log.Warningln("Removing existing tech-detect.yaml")
		os.Remove("nu-tech-detect.yaml")
	}
	err = ioutil.WriteFile("nu-tech-detect.yaml", d, 0644)
	if err != nil {
		log.Fatal("Error writing nu-tech-detect.yaml: ", err.Error())
	}

	log.Printf("Wrote %d matchers to nu-tech-detect.yaml\n", len(matchers))

	// Write out mega-workflow that looks like:
	// id: wordpress-workflow
	// info:
	//   name: Wordpress Security Checks
	//   author: kiblyn11,zomsop82
	//   description: A simple workflow that runs all wordpress related nuclei templates on a given target.

	// workflows:

	//   - template: technologies/tech-detect.yaml
	//     matchers:
	//       - name: wordpress
	//         subtemplates:
	//           - tags: wordpress
	log.Println("Building workflow")
	workflowTemplate := WorkflowTemplate{
		ID: "megazord-workflow",
		Info: TemplateInfo{
			Name:        "tech-detect w/ all checks as tags",
			Author:      "jbertman",
			Description: "A mega-workflow that uses nu-tech-detect and the propagated names as tags to find things",
		},
	}
	var workflows []Workflow
	var workflowMatchers []Matcher
	for _, matcher := range matchers {
		var subtemplates []SubTemplate
		subtemplates = append(subtemplates, SubTemplate{
			Tags: []string{matcher.Name},
		})
		workflowMatchers = append(workflowMatchers, Matcher{
			Name:         matcher.Name,
			Subtemplates: subtemplates,
		})
	}
	var baseWorkflow Workflow = Workflow{
		Template: "nu-tech-detect.yaml",
		Matchers: workflowMatchers,
	}
	workflows = append(workflows, baseWorkflow)
	workflowTemplate.Workflows = workflows

	log.Println("Marshalling workflow")
	d, err = yaml.Marshal(&workflowTemplate)
	if err != nil {
		log.Fatalf("error: %v", err)
	}
	if b, _ := exists("megazord-workflow.yaml"); b {
		log.Warningln("Removing existing megazord-workflow.yaml")
		os.Remove("megazord-workflow.yaml")
	}
	err = ioutil.WriteFile("megazord-workflow.yaml", d, 0644)
	if err != nil {
		log.Fatal("Error writing megazord-workflow.yaml: ", err.Error())
	}
	log.Println("Wrote megazord-workflow.yaml")
}
