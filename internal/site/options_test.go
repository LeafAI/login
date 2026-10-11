package site_test

import (
	"testing"

	"github.com/LeafAI/securl/internal/site"
	_ "github.com/LeafAI/securl/internal/site/gitlab"
	_ "github.com/LeafAI/securl/internal/site/kubesphere"
	_ "github.com/LeafAI/securl/internal/site/noauth"
)

func TestOptionValidate(t *testing.T) {
	strict := site.Option{Key: "login_method", Choices: []string{"auto", "ldap"}}
	if err := strict.Validate("ldap"); err != nil {
		t.Fatalf("valid choice rejected: %v", err)
	}
	if err := strict.Validate(" "); err != nil {
		t.Fatalf("empty means unset and must be valid: %v", err)
	}
	if err := strict.Validate("saml"); err == nil {
		t.Fatal("unknown choice accepted")
	}
	free := site.Option{Key: "identity_provider", Choices: []string{"auto", "local"}, FreeText: true}
	if err := free.Validate("corp-ldap"); err != nil {
		t.Fatalf("free text rejected: %v", err)
	}
}

func TestDriversDescribeTheirOptions(t *testing.T) {
	for driver, key := range map[string]string{"gitlab": "login_method", "kubesphere": "identity_provider"} {
		o, ok := site.OptionOf(driver, key)
		if !ok || o.Label == "" {
			t.Errorf("%s has no described option %q", driver, key)
		}
	}
	if site.OptionsOf("skywalking") != nil || site.OptionsOf("no-such-driver") != nil {
		t.Error("drivers without options must report none")
	}
}
