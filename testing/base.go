// Copyright 2012, 2013 Canonical Ltd.
// Licensed under the AGPLv3, see LICENCE file for details.

package testing

import (
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/juju/collections/set"
	"github.com/juju/loggo"
	jujuos "github.com/juju/os"
	"github.com/juju/os/series"
	"github.com/juju/testing"
	jc "github.com/juju/testing/checkers"
	"github.com/juju/utils"
	"github.com/juju/utils/arch"
	"github.com/juju/utils/featureflag"
	gc "gopkg.in/check.v1"

	"github.com/juju/juju/core/model"
	"github.com/juju/juju/juju/osenv"
	"github.com/juju/juju/jujuclient"
	"github.com/juju/juju/wrench"
)

var logger = loggo.GetLogger("juju.testing")

// JujuOSEnvSuite isolates the tests from Juju environment variables.
// This is intended to be only used by existing suites, usually embedded in
// BaseSuite and in FakeJujuXDGDataHomeSuite. Eventually the tests relying on
// JujuOSEnvSuite will be converted to use the IsolationSuite in
// github.com/juju/testing, and this suite will be removed.
// Do not use JujuOSEnvSuite when writing new tests.
type JujuOSEnvSuite struct {
	oldHomeEnv          string
	oldEnvironment      map[string]string
	initialFeatureFlags string
	regKeyExisted       bool
	regEntryExisted     bool
	oldRegEntryValue    string
}

func (s *JujuOSEnvSuite) SetUpTest(c *gc.C) {
	s.oldEnvironment = make(map[string]string)
	for _, name := range []string{
		osenv.JujuXDGDataHomeEnvKey,
		osenv.JujuControllerEnvKey,
		osenv.JujuModelEnvKey,
		osenv.JujuLoggingConfigEnvKey,
		osenv.JujuFeatureFlagEnvKey,
		osenv.XDGDataHome,
	} {
		s.oldEnvironment[name] = os.Getenv(name)
		os.Setenv(name, "")
	}
	s.oldHomeEnv = utils.Home()
	os.Setenv(osenv.JujuXDGDataHomeEnvKey, c.MkDir())
	err := utils.SetHome("")
	c.Assert(err, jc.ErrorIsNil)

	// Update the feature flag set to be the requested initial set.
	// This works for both windows and unix, even though normally
	// the feature flags on windows are determined using the registry.
	// For tests, setting with the environment variable isolates us
	// from a single resource that was hitting contention during parallel
	// test runs.
	os.Setenv(osenv.JujuFeatureFlagEnvKey, s.initialFeatureFlags)
	featureflag.SetFlagsFromEnvironment(osenv.JujuFeatureFlagEnvKey)
}

func (s *JujuOSEnvSuite) TearDownTest(c *gc.C) {
	for name, value := range s.oldEnvironment {
		os.Setenv(name, value)
	}
	err := utils.SetHome(s.oldHomeEnv)
	c.Assert(err, jc.ErrorIsNil)
}

// SetModelAndController adds a controller, and a model in that controller,
// and sets the controller as the current controller, and the model as the
// current model.
func (s *JujuOSEnvSuite) SetModelAndController(c *gc.C, controllerName, modelName string) {
	store := jujuclient.NewFileClientStore()
	err := store.AddController(controllerName, jujuclient.ControllerDetails{
		ControllerUUID: "fake-uuid",
	})
	c.Assert(err, jc.ErrorIsNil)
	err = store.SetCurrentController(controllerName)
	c.Assert(err, jc.ErrorIsNil)
	err = store.SetModels(controllerName, map[string]jujuclient.ModelDetails{
		modelName: {
			ModelUUID: "fake-model-uuid",
			ModelType: model.IAAS,
		},
	})
	c.Assert(err, jc.ErrorIsNil)
	err = store.SetCurrentModel(controllerName, modelName)
	c.Assert(err, jc.ErrorIsNil)
}

// SkipIfPPC64EL skips the test if the arch is PPC64EL and the
// compiler is gccgo.
func SkipIfPPC64EL(c *gc.C, bugID string) {
	if runtime.Compiler == "gccgo" &&
		arch.NormaliseArch(runtime.GOARCH) == arch.PPC64EL {
		c.Skip(fmt.Sprintf("Test disabled on PPC64EL until fixed - see bug %s", bugID))
	}
}

// SkipIfI386 skips the test if the arch is I386.
func SkipIfI386(c *gc.C, bugID string) {
	if arch.NormaliseArch(runtime.GOARCH) == arch.I386 {
		c.Skip(fmt.Sprintf("Test disabled on I386 until fixed - see bug %s", bugID))
	}
}

// SkipIfS390X skips the test if the arch is S390X.
func SkipIfS390X(c *gc.C, bugID string) {
	if arch.NormaliseArch(runtime.GOARCH) == arch.S390X {
		c.Skip(fmt.Sprintf("Test disabled on S390X until fixed - see bug %s", bugID))
	}
}

// SkipIfWindowsBug skips the test if the OS is Windows.
func SkipIfWindowsBug(c *gc.C, bugID string) {
	if runtime.GOOS == "windows" {
		c.Skip(fmt.Sprintf("Test disabled on Windows until fixed - see bug %s", bugID))
	}
}

// SkipUnlessControllerOS skips the test if the current OS is not a supported
// controller OS.
func SkipUnlessControllerOS(c *gc.C) {
	if jujuos.HostOS() != jujuos.Ubuntu {
		c.Skip("Test disabled for non-controller OS")
	}
}

// SkipFlaky skips the test if there is an open bug for intermittent test failures
func SkipFlaky(c *gc.C, bugID string) {
	c.Skip(fmt.Sprintf("Test disabled until flakiness is fixed - see bug %s", bugID))
}

// SetInitialFeatureFlags sets the feature flags to be in effect for
// the next call to SetUpTest.
func (s *JujuOSEnvSuite) SetInitialFeatureFlags(flags ...string) {
	s.initialFeatureFlags = strings.Join(flags, ",")
}

func (s *JujuOSEnvSuite) SetFeatureFlags(flag ...string) {
	flags := strings.Join(flag, ",")
	if err := os.Setenv(osenv.JujuFeatureFlagEnvKey, flags); err != nil {
		panic(err)
	}
	logger.Debugf("setting feature flags: %s", flags)
	featureflag.SetFlagsFromEnvironment(osenv.JujuFeatureFlagEnvKey)
}

// BaseSuite provides required functionality for all test suites
// when embedded in a gocheck suite type:
// - logger redirect
// - no outgoing network access
// - protection of user's home directory
// - scrubbing of env vars
// TODO (frankban) 2014-06-09: switch to using IsolationSuite.
// NOTE: there will be many tests that fail when you try to change
// to the IsolationSuite that rely on external things in PATH.
type BaseSuite struct {
	oldLtsForTesting string
	testing.CleanupSuite
	testing.LoggingSuite
	JujuOSEnvSuite
	InitialLoggingConfig string
}

func (s *BaseSuite) SetUpSuite(c *gc.C) {
	wrench.SetEnabled(false)
	s.CleanupSuite.SetUpSuite(c)
	s.LoggingSuite.SetUpSuite(c)
	// JujuOSEnvSuite does not have a suite setup.
	s.PatchValue(&utils.OutgoingAccessAllowed, false)
	// LTS-dependent requires new entry upon new LTS release.
	s.oldLtsForTesting = series.SetLatestLtsForTesting("xenial")
}

func (s *BaseSuite) TearDownSuite(c *gc.C) {
	// JujuOSEnvSuite does not have a suite teardown.
	_ = series.SetLatestLtsForTesting(s.oldLtsForTesting)
	s.LoggingSuite.TearDownSuite(c)
	s.CleanupSuite.TearDownSuite(c)
}

func (s *BaseSuite) SetUpTest(c *gc.C) {
	s.CleanupSuite.SetUpTest(c)
	s.LoggingSuite.SetUpTest(c)
	s.JujuOSEnvSuite.SetUpTest(c)
	c.Assert(utils.OutgoingAccessAllowed, gc.Equals, false)
	if s.InitialLoggingConfig != "" {
		err := loggo.ConfigureLoggers(s.InitialLoggingConfig)
		c.Assert(err, jc.ErrorIsNil)
	}

	// We do this to isolate invocations of bash from pulling in the
	// ambient user environment, and potentially affecting the tests.
	// We can't always just use IsolationSuite because we still need
	// PATH and possibly a couple other envars.
	s.PatchEnvironment("BASH_ENV", "")
}

func (s *BaseSuite) TearDownTest(c *gc.C) {
	s.JujuOSEnvSuite.TearDownTest(c)
	s.LoggingSuite.TearDownTest(c)
	s.CleanupSuite.TearDownTest(c)
}

// CheckString compares two strings. If they do not match then the spot
// where they do not match is logged.
func CheckString(c *gc.C, value, expected string) {
	if !c.Check(value, gc.Equals, expected) {
		diffStrings(c, value, expected)
	}
}

func diffStrings(c *gc.C, value, expected string) {
	// If only Go had a diff library.
	vlines := strings.Split(value, "\n")
	elines := strings.Split(expected, "\n")
	vsize := len(vlines)
	esize := len(elines)

	if vsize < 2 || esize < 2 {
		return
	}

	smaller := elines
	if vsize < esize {
		smaller = vlines
	}

	for i := range smaller {
		vline := vlines[i]
		eline := elines[i]
		if vline != eline {
			c.Logf("first mismatched line (%d/%d):", i, len(smaller))
			c.Log("expected: " + eline)
			c.Log("got:      " + vline)
			break
		}
	}
}

// TestCleanup is used to allow DumpTestLogsAfter to take any test suite
// that supports the standard cleanup function.
type TestCleanup interface {
	AddCleanup(func(*gc.C))
}

// DumpTestLogsAfter will write the test logs to stdout if the timeout
// is reached.
func DumpTestLogsAfter(timeout time.Duration, c *gc.C, cleaner TestCleanup) {
	done := make(chan interface{})
	go func() {
		select {
		case <-time.After(timeout):
			fmt.Printf(c.GetTestLog())
		case <-done:
		}
	}()
	cleaner.AddCleanup(func(_ *gc.C) {
		close(done)
	})
}

type PackageManagerStruct struct {
	PackageManager    string
	RepositoryManager string
	PackageQuery      string
}

func GetPackageManager() (s PackageManagerStruct, err error) {
	switch jujuos.HostOS() {
	case jujuos.CentOS:
		s.PackageManager = "yum"
		s.PackageQuery = "yum"
		s.RepositoryManager = "yum-config-manager --add-repo"
	case jujuos.OpenSUSE:
		s.PackageManager = "zypper"
		s.PackageQuery = "zypper"
		s.RepositoryManager = "zypper addrepo"
	case jujuos.Ubuntu:
		s.PackageManager = "apt-get"
		s.PackageQuery = "dpkg-query"
		s.RepositoryManager = "add-apt-repository"
	default:
		s.PackageManager = "apt-get"
		s.PackageQuery = "dpkg-query"
		s.RepositoryManager = "add-apt-repository"
	}
	return s, nil
}

// GetExportedFields return the exported fields of a struct.
func GetExportedFields(arg interface{}) set.Strings {
	t := reflect.TypeOf(arg)
	result := set.NewStrings()

	count := t.NumField()
	for i := 0; i < count; i++ {
		f := t.Field(i)
		// empty PkgPath means exported field.
		// see https://golang.org/pkg/reflect/#StructField
		if f.PkgPath == "" {
			result.Add(f.Name)
		}
	}

	return result
}
