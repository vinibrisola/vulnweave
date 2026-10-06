package main

import "time"

type Dependency struct {
	Name            string   `json:"name"`
	Version         string   `json:"version"`
	Declared        string   `json:"declared,omitempty"`
	Ecosystem       string   `json:"ecosystem"`
	Direct          bool     `json:"direct"`
	Scope           string   `json:"scope,omitempty"`
	Manifest        string   `json:"manifest,omitempty"`
	ControlHint     string   `json:"controlHint,omitempty"`
	DependencyPath  []string `json:"dependencyPath,omitempty"`
	Evidence        []string `json:"evidence,omitempty"`
	ArtifactPaths   []string `json:"artifactPaths,omitempty"`
	DetectionStatus string   `json:"detectionStatus,omitempty"`
}

type Advisory struct {
	ID           string   `json:"id"`
	Aliases      []string `json:"aliases,omitempty"`
	Summary      string   `json:"summary,omitempty"`
	Details      string   `json:"details,omitempty"`
	CVSS         float64  `json:"cvss"`
	Severity     string   `json:"severity"`
	FixedVersion string   `json:"fixedVersion,omitempty"`
	References   []string `json:"references,omitempty"`
}

type RemediationOption struct {
	Version     string `json:"version,omitempty"`
	InstallSpec string `json:"installSpec,omitempty"`
	Kind        string `json:"kind,omitempty"` // registry | vendor-tarball | manual
	Source      string `json:"source,omitempty"`
	EvidenceURL string `json:"evidenceUrl,omitempty"`
	Trusted     bool   `json:"trusted"`
	AutoPlan    bool   `json:"autoPlan"`
	Why         string `json:"why,omitempty"`
}

type RiskItem struct {
	Package                 string              `json:"package"`
	CurrentVersion          string              `json:"currentVersion"`
	DeclaredVersion         string              `json:"declaredVersion,omitempty"`
	CandidateVersion        string              `json:"candidateVersion,omitempty"`
	CandidateWhy            string              `json:"candidateWhy,omitempty"`
	CandidateKind           string              `json:"candidateKind,omitempty"`
	CandidateSpec           string              `json:"candidateSpec,omitempty"`
	CandidateSource         string              `json:"candidateSource,omitempty"`
	CandidateEvidenceURL    string              `json:"candidateEvidenceUrl,omitempty"`
	RemediationOptions      []RemediationOption `json:"remediationOptions,omitempty"`
	Ecosystem               string              `json:"ecosystem"`
	Direct                  bool                `json:"direct"`
	Scope                   string              `json:"scope,omitempty"`
	Runtime                 bool                `json:"runtime"`
	CVSS                    float64             `json:"cvss"`
	Severity                string              `json:"severity"`
	EPSS                    float64             `json:"epss"`
	KEV                     bool                `json:"kev"`
	Priority                string              `json:"priority"`
	Why                     string              `json:"why"`
	Advisories              []Advisory          `json:"advisories"`
	Sources                 []string            `json:"sources"`
	DependencyPath          []string            `json:"dependencyPath,omitempty"`
	Manifest                string              `json:"manifest,omitempty"`
	ControlHint             string              `json:"controlHint,omitempty"`
	ArtifactPaths           []string            `json:"artifactPaths,omitempty"`
	DetectionStatus         string              `json:"detectionStatus,omitempty"`
	AutoRemediationEligible bool                `json:"autoRemediationEligible,omitempty"`
	Origin                  string              `json:"origin,omitempty"`
}

type ProjectInfo struct {
	Root      string `json:"root"`
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem"`
	Manifest  string `json:"manifest"`
	Lockfile  string `json:"lockfile,omitempty"`
}

type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	P0       int `json:"p0"`
	P1       int `json:"p1"`
}

type ScanReport struct {
	CoverageStatus       string                 `json:"coverageStatus"`
	Dependencies         []Dependency           `json:"dependencies,omitempty"`
	AuxiliaryFindings    []RiskItem             `json:"auxiliaryFindings,omitempty"`
	ArtifactDependencies []Dependency           `json:"artifactDependencies,omitempty"`
	ArtifactFindings     []RiskItem             `json:"artifactFindings,omitempty"`
	Reconciliation       map[string]int         `json:"reconciliation,omitempty"`
	SchemaVersion        string                 `json:"schemaVersion"`
	EngineVersion        string                 `json:"engineVersion"`
	BaselineID           string                 `json:"baselineId"`
	GeneratedAt          time.Time              `json:"generatedAt"`
	Mode                 string                 `json:"mode"`
	Project              ProjectInfo            `json:"project"`
	PolicyBlocked        bool                   `json:"policyBlocked"`
	Summary              ScanSummary            `json:"summary"`
	Findings             []RiskItem             `json:"findings"`
	Sources              map[string]string      `json:"sources"`
	Artifacts            map[string]string      `json:"artifacts"`
	Warnings             []string               `json:"warnings,omitempty"`
	Metadata             map[string]interface{} `json:"metadata,omitempty"`
}

type CandidateValidation struct {
	Package              string     `json:"package"`
	CurrentVersion       string     `json:"currentVersion"`
	CandidateVersion     string     `json:"candidateVersion"`
	Ecosystem            string     `json:"ecosystem"`
	Exists               bool       `json:"exists"`
	Vulnerable           bool       `json:"vulnerable"`
	Advisories           []Advisory `json:"advisories,omitempty"`
	Compatibility        string     `json:"compatibility"`
	CompatibilityWhy     string     `json:"compatibilityWhy"`
	Recommended          bool       `json:"recommended"`
	FullScanExecuted     bool       `json:"fullScanExecuted"`
	CheckedAt            time.Time  `json:"checkedAt"`
	Warnings             []string   `json:"warnings,omitempty"`
	InstallSpec          string     `json:"installSpec,omitempty"`
	CandidateKind        string     `json:"candidateKind,omitempty"`
	CandidateSource      string     `json:"candidateSource,omitempty"`
	EvidenceURL          string     `json:"evidenceUrl,omitempty"`
	RepositoryStatus     string     `json:"repositoryStatus,omitempty"`
	RepositoryHTTPStatus int        `json:"repositoryHttpStatus,omitempty"`
	RepositoryError      string     `json:"repositoryError,omitempty"`
	RepositoryFromCache  bool       `json:"repositoryFromCache,omitempty"`
	RetryAfterSeconds    int        `json:"retryAfterSeconds,omitempty"`
	OSVStatus            string     `json:"osvStatus,omitempty"`
	OSVError             string     `json:"osvError,omitempty"`
	ValidationStatus     string     `json:"validationStatus,omitempty"`
}

type PlannedDependencyChange struct {
	Package        string `json:"package"`
	FromSpec       string `json:"fromSpec,omitempty"`
	ToSpec         string `json:"toSpec,omitempty"`
	CurrentVersion string `json:"currentVersion,omitempty"`
	TargetVersion  string `json:"targetVersion,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

type FixPlan struct {
	SchemaVersion   string                    `json:"schemaVersion"`
	ID              string                    `json:"id"`
	CreatedAt       time.Time                 `json:"createdAt"`
	ProjectRoot     string                    `json:"projectRoot"`
	Package         string                    `json:"package"`
	Ecosystem       string                    `json:"ecosystem"`
	CurrentVersion  string                    `json:"currentVersion"`
	TargetVersion   string                    `json:"targetVersion"`
	TargetSpec      string                    `json:"targetSpec,omitempty"`
	TargetKind      string                    `json:"targetKind,omitempty"`
	TargetSource    string                    `json:"targetSource,omitempty"`
	ControlPoint    string                    `json:"controlPoint"`
	CanApply        bool                      `json:"canApply"`
	ManifestPath    string                    `json:"manifestPath"`
	OriginalHash    string                    `json:"originalHash"`
	ProposedHash    string                    `json:"proposedHash"`
	OriginalContent string                    `json:"originalContent"`
	ProposedContent string                    `json:"proposedContent"`
	Diff            string                    `json:"diff"`
	OriginalFiles   map[string]string         `json:"originalFiles"`
	Notes           []string                  `json:"notes,omitempty"`
	Strategy        string                    `json:"strategy,omitempty"`
	RelatedChanges  []PlannedDependencyChange `json:"relatedChanges,omitempty"`
	PlanPath        string                    `json:"planPath,omitempty"`
}

type CommandResult struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExitCode int    `json:"exitCode"`
	Success  bool   `json:"success"`
	Output   string `json:"output,omitempty"`
	Skipped  bool   `json:"skipped,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

type CompatibilitySignal struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Status  string `json:"status"` // pass | warn | fail | info
	Summary string `json:"summary"`
	Detail  string `json:"detail,omitempty"`
}

type TestExecutionSummary struct {
	Known     bool   `json:"known"`
	Framework string `json:"framework,omitempty"`
	Total     int    `json:"total,omitempty"`
	Passed    int    `json:"passed,omitempty"`
	Failed    int    `json:"failed,omitempty"`
	Errors    int    `json:"errors,omitempty"`
	Skipped   int    `json:"skipped,omitempty"`
}

type BinaryAPICompatibility struct {
	Available          bool     `json:"available"`
	CurrentJar         string   `json:"currentJar,omitempty"`
	TargetJar          string   `json:"targetJar,omitempty"`
	CurrentPublicTypes int      `json:"currentPublicTypes,omitempty"`
	TargetPublicTypes  int      `json:"targetPublicTypes,omitempty"`
	RemovedTypes       int      `json:"removedTypes,omitempty"`
	RemovedMembers     int      `json:"removedMembers,omitempty"`
	AddedTypes         int      `json:"addedTypes,omitempty"`
	AddedMembers       int      `json:"addedMembers,omitempty"`
	SampleRemoved      []string `json:"sampleRemoved,omitempty"`
	Detail             string   `json:"detail,omitempty"`
}

type ArtifactCompatibilityEvidence struct {
	Checked       bool     `json:"checked"`
	TargetPresent bool     `json:"targetPresent"`
	OldPresent    bool     `json:"oldPresent"`
	TargetPaths   []string `json:"targetPaths,omitempty"`
	OldPaths      []string `json:"oldPaths,omitempty"`
	Detail        string   `json:"detail,omitempty"`
}

type CompatibilityReport struct {
	Confidence    string                         `json:"confidence"` // high | medium | low | blocked
	Headline      string                         `json:"headline"`
	ChangeType    string                         `json:"changeType"`
	BlastRadius   string                         `json:"blastRadius"`
	GeneratedBy   string                         `json:"generatedBy"`
	Signals       []CompatibilitySignal          `json:"signals"`
	Tests         *TestExecutionSummary          `json:"tests,omitempty"`
	BinaryAPI     *BinaryAPICompatibility        `json:"binaryApi,omitempty"`
	Artifact      *ArtifactCompatibilityEvidence `json:"artifact,omitempty"`
	ResidualRisks []string                       `json:"residualRisks,omitempty"`
}

type FixExecution struct {
	SchemaVersion        string               `json:"schemaVersion"`
	PlanID               string               `json:"planId"`
	TempRoot             string               `json:"tempRoot"`
	SandboxManifestPath  string               `json:"sandboxManifestPath,omitempty"`
	SandboxManifestHash  string               `json:"sandboxManifestHash,omitempty"`
	SandboxPatchVerified bool                 `json:"sandboxPatchVerified"`
	LockResolution       CommandResult        `json:"lockResolution"`
	Build                CommandResult        `json:"build"`
	BaselineBuild        *CommandResult       `json:"baselineBuild,omitempty"`
	BuildAssessment      string               `json:"buildAssessment,omitempty"`
	Tests                CommandResult        `json:"tests"`
	Rescan               *ScanReport          `json:"rescan,omitempty"`
	Before               *RiskItem            `json:"before,omitempty"`
	After                *RiskItem            `json:"after,omitempty"`
	ChangedFiles         []string             `json:"changedFiles"`
	ReadyToApply         bool                 `json:"readyToApply"`
	Blockers             []string             `json:"blockers,omitempty"`
	Warnings             []string             `json:"warnings,omitempty"`
	ExecutionPath        string               `json:"executionPath,omitempty"`
	Compatibility        *CompatibilityReport `json:"compatibility,omitempty"`
}
