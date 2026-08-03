package builtin

import (
	"testing"

	"github.com/harshmaur/audr/internal/parse"
)

func TestOpenClawDashboardNotificationUsernameStoredXSS(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function fetchNotifications() {
  const res = await authFetch(API_BASE + '/api/notifications?limit=50');
  const data = await res.json();
  const body = document.getElementById('notifPanelBody');
  body.innerHTML = data.events.map(e => {
    const icon = notifIcons[e.event] || 'event';
    const detail = e.username ? ' (' + e.username + ')' : '';
    return '<div class="notif-item">' + icon + detail + '</div>';
  }).join('');
}
</script>`)
	doc := parse.Parse("/opt/openclaw-dashboard/index.html", raw)
	if !fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("expected OpenClaw Dashboard notification XSS finding; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardNotificationArrowTemplateVariant(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
const loadEvents = async () => {
  const response = await authFetch('/api/notifications?limit=20');
  const payload = await response.json();
  notifPanelBody.innerHTML = payload.events.map(item => ` + "`<div>${item.userName}</div>`" + `).join("");
};
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if !fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("expected equivalent username-to-innerHTML variant to fire; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardNotificationTextContentDoesNotFire(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function fetchNotifications() {
  const res = await authFetch(API_BASE + '/api/notifications?limit=50');
  const data = await res.json();
  const body = document.getElementById('notifPanelBody');
  for (const event of data.events) {
    const row = document.createElement('div');
    row.textContent = event.username || '';
    body.appendChild(row);
  }
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("textContent rendering should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardEscapedUsernameDoesNotFire(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function fetchNotifications() {
  const response = await authFetch('/api/notifications?limit=20');
  const payload = await response.json();
  notifPanelBody.innerHTML = payload.events.map(item => '<div>' + escapeHTML(item.username) + '</div>').join('');
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("escaped username rendering should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardIndirectRowsAssignmentVariant(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function loadNotifications() {
  const response = await authFetch('/api/notifications?limit=20');
  const payload = await response.json();
  const rows = payload.events.map(item => '<div>' + item.username + '</div>').join('');
  notifPanelBody.innerHTML = rows;
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if !fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("expected indirect rows-to-innerHTML flow to fire; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardIndirectMapThenJoinAtSinkVariant(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function loadNotifications() {
  const response = await authFetch('/api/notifications?limit=20');
  const payload = await response.json();
  const rows = payload.events.map(item => '<div>' + item.username + '</div>');
  notifPanelBody.innerHTML = rows.join('');
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if !fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("expected map-then-join-at-sink flow to fire; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardInnerHTMLReadDoesNotFire(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function loadNotifications() {
  const response = await authFetch('/api/notifications?limit=20')
  const payload = await response.json()
  const previous = notifPanelBody.innerHTML
  const rows = payload.events.map(item => '<div>' + item.username + '</div>')
  console.log(previous, rows)
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("innerHTML read without a sink assignment should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardEarlierSemicolonlessInnerHTMLWriteDoesNotFire(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function loadNotifications() {
  const response = await authFetch('/api/notifications?limit=20')
  const payload = await response.json()
  notifPanelBody.innerHTML = '<p>Loading</p>'
  const rows = payload.events.map(item => '<div>' + item.username + '</div>')
  console.log(rows)
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("unrelated earlier innerHTML write should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestOpenClawDashboardEscapedUsernameVariableDoesNotFire(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Agent Dashboard</title>
<div id="notifPanelBody"></div>
<script>
async function fetchNotifications() {
  const response = await authFetch('/api/notifications?limit=20');
  const payload = await response.json();
  notifPanelBody.innerHTML = payload.events.map(item => {
    const safeUsername = escapeHTML(item.username);
    return '<div>' + safeUsername + '</div>';
  }).join('');
}
</script>`)
	doc := parse.Parse("/srv/agent-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("escaped username variable should be clean; rules fired: %v", applyRule(doc))
	}
}

func TestUnrelatedNotificationTemplateDoesNotFireOpenClawDashboardRule(t *testing.T) {
	raw := []byte(`<!doctype html>
<title>Other Dashboard</title>
<script>
const body = document.getElementById('notifications');
body.innerHTML = data.events.map(e => '<div>' + e.username + '</div>').join('');
</script>`)
	doc := parse.Parse("/repo/openclaw-dashboard/index.html", raw)
	if fired(doc, "openclaw-dashboard-notification-username-stored-xss") {
		t.Fatalf("unrelated notification template should be clean; rules fired: %v", applyRule(doc))
	}
}
