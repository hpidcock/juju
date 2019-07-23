package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/printer"
	"go/token"
	"io/ioutil"
	"log"
	"path"
	"reflect"
	"strconv"
	"strings"

	govmomimethods "github.com/vmware/govmomi/vim25/methods"
)

const (
	pkg = "github.com/vmware/govmomi/vim25/methods"
)

func main() {
	t := reflect.TypeOf(govmomimethods.CreateVM_TaskBody{})
	bp, err := build.Default.Import(t.PkgPath(), "", build.ImportComment)
	if err != nil {
		log.Fatal(err)
	}

	//importsUsed := new(map[string]string)
	interfaceMethods := []string{}
	implMethods := []string{}
	imports := []*ast.ImportSpec{}
	packagesUsed := []*ast.Ident{}

	for _, f := range bp.GoFiles {
		fset := token.NewFileSet()
		p := path.Join(bp.Dir, f)
		srcBytes, err := ioutil.ReadFile(p)
		if err != nil {
			log.Fatalf("failed reading %s %v", p, err)
		}
		astFile, err := parser.ParseFile(fset, "", srcBytes, parser.ParseComments)
		if err != nil {
			log.Fatalf("failed parsing %s %v", p, err)
		}

		imports = append(imports, astFile.Imports...)
		for _, decl := range astFile.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}

			// nil receviers only.
			if funcDecl.Recv != nil {
				continue
			}

			for _, param := range funcDecl.Type.Params.List {
				pkg := resolvePkg(param.Type)
				if pkg != nil {
					packagesUsed = append(packagesUsed, pkg)
				}
			}

			for _, param := range funcDecl.Type.Results.List {
				pkg := resolvePkg(param.Type)
				if pkg != nil {
					packagesUsed = append(packagesUsed, pkg)
				}
			}

			methodType := &bytes.Buffer{}
			printer.Fprint(methodType, fset, funcDecl.Type)
			funcSig := strings.TrimPrefix(methodType.String(), "func")

			method := &bytes.Buffer{}
			fmt.Fprintf(method, "%s%s", funcDecl.Name.Name, funcSig)
			interfaceMethods = append(interfaceMethods, method.String())

			implMethod := &bytes.Buffer{}
			fmt.Fprintf(implMethod, "func (_ *ImplContext) %s%s {\n", funcDecl.Name, funcSig)

			params := []string{}
			for _, param := range funcDecl.Type.Params.List {
				for _, name := range param.Names {
					params = append(params, name.Name)
				}
			}

			fmt.Fprintf(implMethod, "\treturn %s.%s(%s)\n", bp.Name, funcDecl.Name, strings.Join(params, ", "))
			fmt.Fprintf(implMethod, "}\n")

			implMethods = append(implMethods, implMethod.String())
		}
	}

	neededIdent := make(map[string]*ast.Ident)
	for _, ident := range packagesUsed {
		neededIdent[ident.Name] = ident
	}
	imported := make(map[string]*ast.ImportSpec)
	for _, importSpec := range imports {
		if importSpec.Name != nil {
			imported[importSpec.Name.Name] = importSpec
			continue
		}
		p, err := strconv.Unquote(importSpec.Path.Value)
		if err != nil {
			log.Fatal(err)
		}
		ip, err := build.Default.Import(p, bp.Dir, build.ImportComment)
		if err != nil {
			log.Fatal(err)
		}
		imported[ip.Name] = importSpec
	}

	importBlock := &bytes.Buffer{}
	fmt.Fprint(importBlock, "import (\n")
	fmt.Fprintf(importBlock, "\t%s \"%s\"\n", bp.Name, pkg)
	for _, ident := range neededIdent {
		importSpec, found := imported[ident.Name]
		if found {
			fmt.Fprintf(importBlock, "\t%s %s\n", ident.Name, importSpec.Path.Value)
		}
	}
	fmt.Fprint(importBlock, ")\n\n")

	output := &bytes.Buffer{}
	fmt.Fprint(output, "package api\n\n")
	fmt.Fprint(output, importBlock.String())
	fmt.Fprint(output, "type Context interface {\n\t")
	fmt.Fprint(output, strings.Join(interfaceMethods, "\n\t"))
	fmt.Fprint(output, "\n}\n\n")
	fmt.Fprint(output, "type ImplContext struct{}\n")
	fmt.Fprint(output, strings.Join(implMethods, "\n"))
	ioutil.WriteFile("generated_api.go", output.Bytes(), 0600)
}

func resolvePkg(node ast.Node) *ast.Ident {
	switch s := node.(type) {
	case *ast.StarExpr:
		return resolvePkg(s.X)
	case *ast.SelectorExpr:
		return resolvePkg(s.X)
	case *ast.Ident:
		return s
	}
	return nil
}
