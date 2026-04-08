package inspector

import (
	"os"
	"strings"
	"testing"
)

// loadFixture reads a testdata file and returns its content as a string.
func loadFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatalf("loadFixture %q: %v", name, err)
	}
	return string(b)
}

// ruleMatched returns true if any match in the result has the given ruleID.
func ruleMatched(matches []Match, ruleID string) bool {
	for _, m := range matches {
		if m.RuleID == ruleID {
			return true
		}
	}
	return false
}

// ── application.properties ───────────────────────────────────────────────────

func TestSpringProperties_DSPassword(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.properties: expected generic-secret to match spring.datasource.password")
	}
}

func TestSpringProperties_DSFullURI(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	result := eng.Inspect(content)
	if !result.Blocked {
		t.Error("application.properties: expected db-connection-string to block embedded credentials in JDBC URI")
	}
	if !ruleMatched(result.Matches, "db-connection-string") {
		t.Error("application.properties: db-connection-string rule did not fire on JDBC URI with credentials")
	}
}

func TestSpringProperties_AWSAccessKey(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	result := eng.Inspect(content)
	if !ruleMatched(result.Matches, "aws-access-key") {
		t.Error("application.properties: expected aws-access-key to match cloud.aws.credentials.access-key")
	}
}

func TestSpringProperties_OAuthClientSecret(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.properties: expected generic-secret to match oauth2 client-secret")
	}
}

func TestSpringProperties_JWTSecret(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.properties: expected generic-secret to match jwt.secret")
	}
}

func TestSpringProperties_RedisPassword(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.properties: expected generic-secret to match spring.redis.password")
	}
}

func TestSpringProperties_MailPassword(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.properties: expected generic-secret to match spring.mail.password")
	}
}

func TestSpringProperties_Email(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.properties")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "email") {
		t.Error("application.properties: expected email rule to match noreply@example.com")
	}
}

func TestSpringProperties_SafeValuesNotFlagged(t *testing.T) {
	eng := New()
	// Safe properties only — no secrets
	safe := `server.port=8080
spring.profiles.active=production
logging.level.root=INFO
spring.jpa.database-platform=org.hibernate.dialect.MySQL8Dialect`
	_, matches := eng.RedactText(safe)
	if len(matches) > 0 {
		t.Errorf("safe properties: unexpected matches: %+v", matches)
	}
}

func TestSpringProperties_RedactedDoesNotContainSecrets(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true) // agent mode applies all rules including block-mode (db-connection-string)
	content := loadFixture(t, "application.properties")
	redacted, _ := eng.RedactText(content)
	secrets := []string{
		"Sup3rS3cr3tDBPass!",
		"r3d1sS3cr3tPass",
		"gmailAppPassw0rd!",
		"myJ4tS3cr3tK3yF0rHS512Signing!!",
	}
	for _, s := range secrets {
		if strings.Contains(redacted, s) {
			t.Errorf("application.properties: secret %q was not redacted", s)
		}
	}
}

// ── application.yml ───────────────────────────────────────────────────────────

func TestSpringYAML_DSPassword(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.yml: expected generic-secret to match spring.datasource.password")
	}
}

func TestSpringYAML_DSFullURI(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	result := eng.Inspect(content)
	if !result.Blocked {
		t.Error("application.yml: expected db-connection-string to block embedded credentials in JDBC URI")
	}
	if !ruleMatched(result.Matches, "db-connection-string") {
		t.Error("application.yml: db-connection-string rule did not fire on JDBC URI with credentials")
	}
}

func TestSpringYAML_AWSAccessKey(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	result := eng.Inspect(content)
	if !ruleMatched(result.Matches, "aws-access-key") {
		t.Error("application.yml: expected aws-access-key to match cloud.aws.credentials.access-key")
	}
}

func TestSpringYAML_RedisPassword(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.yml: expected generic-secret to match spring.redis.password")
	}
}

func TestSpringYAML_OAuthClientSecret(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.yml: expected generic-secret to match oauth2 client-secret")
	}
}

func TestSpringYAML_JWTSecret(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "generic-secret") {
		t.Error("application.yml: expected generic-secret to match jwt.secret")
	}
}

func TestSpringYAML_Email(t *testing.T) {
	eng := New()
	content := loadFixture(t, "application.yml")
	_, matches := eng.RedactText(content)
	if !ruleMatched(matches, "email") {
		t.Error("application.yml: expected email rule to match noreply@example.com")
	}
}

func TestSpringYAML_SafeValuesNotFlagged(t *testing.T) {
	eng := New()
	safe := `server:
  port: 8080
logging:
  level:
    root: INFO`
	_, matches := eng.RedactText(safe)
	if len(matches) > 0 {
		t.Errorf("safe yaml: unexpected matches: %+v", matches)
	}
}

func TestSpringYAML_RedactedDoesNotContainSecrets(t *testing.T) {
	eng := New()
	eng.SetAgentMode(true) // agent mode applies all rules including block-mode (db-connection-string)
	content := loadFixture(t, "application.yml")
	redacted, _ := eng.RedactText(content)
	secrets := []string{
		"Sup3rS3cr3tDBPass!",
		"r3d1sS3cr3tPass",
		"gmailAppPassw0rd!",
		"myJ4tS3cr3tK3yF0rHS512Signing!!",
	}
	for _, s := range secrets {
		if strings.Contains(redacted, s) {
			t.Errorf("application.yml: secret %q was not redacted", s)
		}
	}
}

// ── Oracle JDBC ───────────────────────────────────────────────────────────────

func TestOracleJDBC_Blocked(t *testing.T) {
	eng := New()
	cases := []string{
		// thin driver with user/pass@host:port:sid
		"jdbc:oracle:thin:appuser/s3cr3tPass@prod-db.example.com:1521:ORCL",
		// thin driver with user/pass@//host:port/service
		"jdbc:oracle:thin:appuser/s3cr3tPass@//prod-db.example.com:1521/myservice",
		// oci driver
		"jdbc:oracle:oci:appuser/s3cr3tPass@prod-db.example.com:1521:ORCL",
	}
	for _, c := range cases {
		result := eng.Inspect(c)
		if !result.Blocked {
			t.Errorf("oracle jdbc %q: expected block, got clean", c)
		}
		if !ruleMatched(result.Matches, "db-connection-string") {
			t.Errorf("oracle jdbc %q: db-connection-string rule did not fire", c)
		}
	}
}

func TestOracleJDBC_NoCredentials_NotBlocked(t *testing.T) {
	eng := New()
	// Oracle URI without embedded credentials should not match
	cases := []string{
		"jdbc:oracle:thin:@prod-db.example.com:1521:ORCL",
		"jdbc:oracle:thin:@//prod-db.example.com:1521/myservice",
	}
	for _, c := range cases {
		result := eng.Inspect(c)
		if ruleMatched(result.Matches, "db-connection-string") {
			t.Errorf("oracle jdbc no-creds %q: unexpected db-connection-string match", c)
		}
	}
}

func TestOracleJDBC_InSpringBootFixtures(t *testing.T) {
	eng := New()
	for _, fixture := range []string{"application.properties", "application.yml"} {
		content := loadFixture(t, fixture)
		result := eng.Inspect(content)
		if !ruleMatched(result.Matches, "db-connection-string") {
			t.Errorf("%s: expected db-connection-string to match Oracle JDBC URI", fixture)
		}
	}
}
