package mcpserver

import (
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
)

// Driver options live on the process-wide driver instances: undo them so other tests are unaffected.
func resetDriverOptions(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		for _, name := range []string{"gitlab", "kubesphere"} {
			if d, err := site.Resolve(name, nil); err == nil {
				d.(site.Configurable).Configure(nil)
			}
		}
	})
}

func TestApplySiteOptionsRejectsUnknownOptionNamesAndValues(t *testing.T) {
	resetDriverOptions(t)
	cases := []struct {
		name string
		opts map[string]map[string]string
		want []string
	}{
		{"typo in option name", map[string]map[string]string{"gitlab": {"login_methd": "ldap"}}, []string{"login_methd", "login_method"}},
		{"bad choice", map[string]map[string]string{"gitlab": {"login_method": "ladp"}}, []string{"login_method", "auto, ldap, standard"}},
		{"unknown driver", map[string]map[string]string{"gitlabb": {"login_method": "ldap"}}, []string{"gitlabb"}},
		{"driver without options", map[string]map[string]string{"jenkins": {"x": "y"}}, []string{"jenkins"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ApplySiteOptions(&config.Config{SiteOptions: tc.opts})
			if err == nil {
				t.Fatal("must be rejected")
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error should mention %q: %v", w, err)
				}
			}
		})
	}
}

func TestApplySiteOptionsAcceptsValidOnesAndFreeText(t *testing.T) {
	resetDriverOptions(t)
	ok := &config.Config{SiteOptions: map[string]map[string]string{
		"gitlab":     {"login_method": "ldap", "ldap_provider": "ldapmain"},
		"kubesphere": {"identity_provider": "my-custom-idp"},
	}}
	if err := ApplySiteOptions(ok); err != nil {
		t.Fatal(err)
	}
}
