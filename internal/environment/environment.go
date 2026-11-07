// Package environment describes the user's infrastructure (services,
// frameworks, platforms) that news items are filtered against, along with
// optional analyst instructions for Claude.
package environment

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

var exposures = []string{"internet", "internal", "local"}

// relevances lists the relevance levels Claude assigns to findings.
var relevances = []string{"critical", "high", "medium", "low"}

// defaultResearchRelevance is used when research_relevance is not set.
var defaultResearchRelevance = []string{"critical", "high"}

// GitHub Advisory Database filter values.
var (
	githubEcosystems = []string{"go", "npm", "pip", "maven", "nuget", "composer", "rubygems", "rust", "erlang", "actions", "pub", "swift", "other"}
	githubSeverities = []string{"low", "medium", "high", "critical", "unknown"}
	githubTypes      = []string{"reviewed", "unreviewed", "malware"}
)

type Environment struct {
	// Prompt overrides the built-in analyst instructions when set.
	Prompt string `yaml:"prompt,omitempty"`
	// ResearchPrompt overrides the built-in research instructions when set.
	ResearchPrompt string `yaml:"research_prompt,omitempty"`
	// ResearchRelevance lists the relevance levels that get researched
	// online. Load sets it to critical and high when the file leaves it out;
	// an empty list turns research off.
	ResearchRelevance []string    `yaml:"research_relevance,omitempty"`
	Context           string      `yaml:"context,omitempty"`
	Stack             []Component `yaml:"stack"`
	Advisories        Advisories  `yaml:"advisories,omitempty"`
}

type Component struct {
	Name     string `yaml:"name"`
	Vendor   string `yaml:"vendor,omitempty"`
	Type     string `yaml:"type,omitempty"`
	Version  string `yaml:"version,omitempty"`
	Exposure string `yaml:"exposure,omitempty"`
	Notes    string `yaml:"notes,omitempty"`
}

// Advisories lists the advisory database queries to run. Each list maps to
// one endpoint; the lookback window, paging and auth are added by the
// advisory package.
type Advisories struct {
	// GitHub queries GET /advisories, the global GitHub Advisory Database.
	GitHub []GitHubQuery `yaml:"github,omitempty"`
	// GitHubRepos lists owner/name repositories whose own advisories are
	// read from GET /repos/{owner}/{repo}/security-advisories.
	GitHubRepos []string `yaml:"github_repos,omitempty"`
	// OSV queries POST https://api.osv.dev/v1/query.
	OSV []OSVQuery `yaml:"osv,omitempty"`
}

// Len returns the number of queries.
func (a Advisories) Len() int {
	return len(a.GitHub) + len(a.GitHubRepos) + len(a.OSV)
}

// GitHubQuery holds the filters of one GET /advisories request. Field names
// match the API parameters.
type GitHubQuery struct {
	Name      string   `yaml:"name,omitempty"`
	Ecosystem string   `yaml:"ecosystem,omitempty"`
	Affects   []string `yaml:"affects,omitempty"` // package names, each may end in @version
	Severity  string   `yaml:"severity,omitempty"`
	Type      string   `yaml:"type,omitempty"`
	CWEs      []string `yaml:"cwes,omitempty"`
}

// OSVQuery selects a package either by ecosystem and name (with an optional
// version) or by purl.
type OSVQuery struct {
	Name      string `yaml:"name,omitempty"`
	Ecosystem string `yaml:"ecosystem,omitempty"`
	Package   string `yaml:"package,omitempty"`
	Version   string `yaml:"version,omitempty"`
	PURL      string `yaml:"purl,omitempty"`
}

func Load(path string) (*Environment, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading environment file: %w", err)
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var env Environment
	if err := dec.Decode(&env); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parsing environment file %s: %w", path, err)
	}
	if env.ResearchRelevance == nil {
		env.ResearchRelevance = defaultResearchRelevance
	}
	if err := env.validate(); err != nil {
		return nil, fmt.Errorf("invalid environment file %s: %w", path, err)
	}
	return &env, nil
}

func (e *Environment) validate() error {
	if len(e.Stack) == 0 {
		return errors.New("stack must contain at least one component")
	}

	var errs []error
	for _, r := range e.ResearchRelevance {
		if !slices.Contains(relevances, r) {
			errs = append(errs, fmt.Errorf("research_relevance: %q must be one of %v", r, relevances))
		}
	}
	for i, c := range e.Stack {
		if c.Name == "" {
			errs = append(errs, fmt.Errorf("stack[%d]: name is required", i))
		}
		if c.Exposure != "" && !slices.Contains(exposures, c.Exposure) {
			errs = append(errs, fmt.Errorf("stack[%d] (%s): exposure %q must be one of %v", i, c.Name, c.Exposure, exposures))
		}
	}
	errs = append(errs, e.Advisories.validate()...)
	return errors.Join(errs...)
}

func (a Advisories) validate() []error {
	var errs []error
	for i, q := range a.GitHub {
		label := queryLabel("github", i, q.Name)
		if q.Ecosystem == "" && len(q.Affects) == 0 && len(q.CWEs) == 0 {
			errs = append(errs, fmt.Errorf("%s: set at least one of ecosystem, affects or cwes", label))
		}
		if q.Ecosystem != "" && !slices.Contains(githubEcosystems, q.Ecosystem) {
			errs = append(errs, fmt.Errorf("%s: ecosystem %q must be one of %v", label, q.Ecosystem, githubEcosystems))
		}
		if q.Severity != "" && !slices.Contains(githubSeverities, q.Severity) {
			errs = append(errs, fmt.Errorf("%s: severity %q must be one of %v", label, q.Severity, githubSeverities))
		}
		if q.Type != "" && !slices.Contains(githubTypes, q.Type) {
			errs = append(errs, fmt.Errorf("%s: type %q must be one of %v", label, q.Type, githubTypes))
		}
	}
	for i, repo := range a.GitHubRepos {
		owner, name, ok := strings.Cut(repo, "/")
		if !ok || owner == "" || name == "" || strings.Contains(name, "/") {
			errs = append(errs, fmt.Errorf("advisories.github_repos[%d]: %q must be owner/name", i, repo))
		}
	}
	for i, q := range a.OSV {
		label := queryLabel("osv", i, q.Name)
		byPURL := q.PURL != "" && q.Ecosystem == "" && q.Package == ""
		byPackage := q.PURL == "" && q.Ecosystem != "" && q.Package != ""
		if !byPURL && !byPackage {
			errs = append(errs, fmt.Errorf("%s: set either purl or ecosystem+package", label))
		}
		if q.Version != "" && q.PURL != "" {
			errs = append(errs, fmt.Errorf("%s: version needs ecosystem+package; put it in the purl instead", label))
		}
	}
	return errs
}

func queryLabel(list string, i int, name string) string {
	if name == "" {
		return fmt.Sprintf("advisories.%s[%d]", list, i)
	}
	return fmt.Sprintf("advisories.%s[%d] (%s)", list, i, name)
}

// Describe returns the context and stack as YAML for embedding in prompts.
// The prompts themselves are left out.
func (e *Environment) Describe() (string, error) {
	out, err := yaml.Marshal(struct {
		Context string      `yaml:"context,omitempty"`
		Stack   []Component `yaml:"stack"`
	}{e.Context, e.Stack})
	if err != nil {
		return "", err
	}
	return string(out), nil
}
