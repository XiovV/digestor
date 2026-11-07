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

	"go.yaml.in/yaml/v3"
)

var exposures = []string{"internet", "internal", "local"}

// relevances lists the relevance levels Claude assigns to findings.
var relevances = []string{"critical", "high", "medium", "low"}

// defaultResearchRelevance is used when research_relevance is not set.
var defaultResearchRelevance = []string{"critical", "high"}

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
}

type Component struct {
	Name     string `yaml:"name"`
	Vendor   string `yaml:"vendor,omitempty"`
	Type     string `yaml:"type,omitempty"`
	Version  string `yaml:"version,omitempty"`
	Exposure string `yaml:"exposure,omitempty"`
	Notes    string `yaml:"notes,omitempty"`
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
	return errors.Join(errs...)
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
