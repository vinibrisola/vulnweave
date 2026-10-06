package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func printJSON(v interface{}) { b, _ := json.MarshalIndent(v, "", "  "); fmt.Println(string(b)) }
func fail(err error)          { fmt.Fprintln(os.Stderr, err.Error()); os.Exit(1) }

func main() {
	if len(os.Args) < 2 {
		fmt.Println("VulnWeave Engine " + engineVersion + "\ncommands: scan, validate-candidate, plan-fix, execute-plan, apply-plan, detect, version")
		return
	}
	switch os.Args[1] {
	case "version":
		fmt.Println(engineVersion)
	case "detect":
		fs := flag.NewFlagSet("detect", flag.ExitOnError)
		root := fs.String("project", ".", "project root")
		_ = fs.Parse(os.Args[2:])
		p, err := detectProject(*root)
		if err != nil {
			fail(err)
		}
		printJSON(p)
	case "scan":
		fs := flag.NewFlagSet("scan", flag.ExitOnError)
		root := fs.String("project", ".", "project root")
		mode := fs.String("mode", "full", "full")
		_ = fs.Parse(os.Args[2:])
		r, err := scanProject(*root, *mode)
		if err != nil {
			fail(err)
		}
		printJSON(r)
	case "validate-candidate":
		fs := flag.NewFlagSet("validate-candidate", flag.ExitOnError)
		root := fs.String("project", ".", "project root")
		pkg := fs.String("package", "", "package")
		cur := fs.String("current", "", "current version")
		target := fs.String("target", "", "candidate version")
		eco := fs.String("ecosystem", "", "npm|Maven")
		_ = fs.Parse(os.Args[2:])
		if *pkg == "" || *target == "" {
			fail(fmt.Errorf("--package e --target são obrigatórios"))
		}
		r, err := validateCandidate(*root, *pkg, *cur, *target, *eco)
		if err != nil {
			fail(err)
		}
		printJSON(r)
	case "plan-fix":
		fs := flag.NewFlagSet("plan-fix", flag.ExitOnError)
		root := fs.String("project", ".", "project root")
		pkg := fs.String("package", "", "package")
		cur := fs.String("current", "", "current version")
		target := fs.String("target", "", "target version")
		targetSpec := fs.String("target-spec", "", "install spec (optional, e.g. trusted vendor tarball)")
		targetKind := fs.String("target-kind", "", "registry|vendor-tarball|manual")
		targetSource := fs.String("target-source", "", "trusted source label")
		_ = fs.Parse(os.Args[2:])
		if *pkg == "" || *target == "" {
			fail(fmt.Errorf("--package e --target são obrigatórios"))
		}
		r, err := planFix(*root, *pkg, *cur, *target, *targetSpec, *targetKind, *targetSource)
		if err != nil {
			fail(err)
		}
		printJSON(r)
	case "execute-plan":
		fs := flag.NewFlagSet("execute-plan", flag.ExitOnError)
		plan := fs.String("plan", "", "plan json")
		build := fs.Bool("build", true, "run build")
		tests := fs.Bool("tests", true, "run tests")
		_ = fs.Parse(os.Args[2:])
		if *plan == "" {
			fail(fmt.Errorf("--plan obrigatório"))
		}
		r, err := executePlan(*plan, *build, *tests)
		if err != nil {
			fail(err)
		}
		printJSON(r)
	case "apply-plan":
		fs := flag.NewFlagSet("apply-plan", flag.ExitOnError)
		plan := fs.String("plan", "", "plan json")
		execution := fs.String("execution", "", "execution json")
		_ = fs.Parse(os.Args[2:])
		if *plan == "" || *execution == "" {
			fail(fmt.Errorf("--plan e --execution obrigatórios"))
		}
		r, err := applyPlan(*plan, *execution)
		if err != nil {
			fail(err)
		}
		printJSON(r)
	default:
		fail(fmt.Errorf("comando desconhecido: %s", os.Args[1]))
	}
}
