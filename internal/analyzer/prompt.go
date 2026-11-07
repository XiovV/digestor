package analyzer

import (
	"strings"
	"text/template"

	"github.com/XiovV/digestor/internal/environment"
	"github.com/XiovV/digestor/internal/feed"
)

// defaultPrompt holds the analyst instructions used when the environment
// file does not set its own prompt.
const defaultPrompt = `You are a security analyst responsible for the environment described below. You receive a batch of security news items and decide which ones I need to know about.

Rate each relevant item:
- critical: patch or mitigate today.
- high: patch or mitigate this week.
- medium: handle in the next patch window.
- low: worth knowing, no action needed.

Internet-facing components and vulnerabilities that are actively exploited raise the priority. Skip generic news, opinion pieces and anything that does not affect a component in my stack. If an item names affected versions and my version is outside that range, lower its rating or skip it.`

// The parts after {{.Instructions}} are fixed: the Go code depends on them.
var filterTmpl = template.Must(template.New("filter").Parse(`{{.Instructions}}

<environment>
{{.Environment}}</environment>

<items>
{{range $i, $it := .Items}}[{{$i}}] {{$it.Title}}
Source: {{$it.FeedTitle}}
Link: {{$it.Link}}
Published: {{$it.Published.Format "2006-01-02"}}
{{$it.Summary}}

{{end}}</items>

If several items cover the same story, rate only one of them and mark the others as not relevant with the reason "duplicate of [<item number>]".

Respond with ONLY a JSON array, no prose, with one element for every item. For an item that matters to me:
{"index": <item number>, "relevance": "critical|high|medium|low", "affected": ["<component name from the stack>"], "summary": "<one or two sentences on why it matters to me>"}
For an item that does not:
{"index": <item number>, "relevance": "none", "summary": "<a few words on why it was skipped>"}
`))

// defaultResearchPrompt holds the research instructions used when the
// environment file does not set its own research_prompt.
const defaultResearchPrompt = `You are a security analyst. The news item below was flagged as relevant to my environment.

Research it online: affected versions, CVE identifiers, whether it is actively exploited, and remediation steps. Focus on what applies to my environment.`

// The parts after {{.Instructions}} are fixed: the Go code depends on them.
var researchTmpl = template.Must(template.New("research").Parse(`{{.Instructions}}

<environment>
{{.Environment}}</environment>

<item>
Title: {{.Finding.Item.Title}}
Link: {{.Finding.Item.Link}}
Affected components: {{range .Finding.Affected}}{{.}} {{end}}
Initial assessment: {{.Finding.Summary}}
</item>

Respond with ONLY a JSON object, no prose:
{"research": "<concise findings and recommended actions>", "references": ["<url>"]}
`))

func filterPrompt(items []feed.Item, env *environment.Environment) (string, error) {
	desc, err := env.Describe()
	if err != nil {
		return "", err
	}

	instructions := strings.TrimSpace(env.Prompt)
	if instructions == "" {
		instructions = defaultPrompt
	}

	return render(filterTmpl, map[string]any{
		"Instructions": instructions,
		"Environment":  desc,
		"Items":        items,
	})
}

func researchPrompt(f Finding, env *environment.Environment) (string, error) {
	desc, err := env.Describe()
	if err != nil {
		return "", err
	}
	instructions := strings.TrimSpace(env.ResearchPrompt)
	if instructions == "" {
		instructions = defaultResearchPrompt
	}
	return render(researchTmpl, map[string]any{
		"Instructions": instructions,
		"Environment":  desc,
		"Finding":      f,
	})
}

func render(t *template.Template, data any) (string, error) {
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}
