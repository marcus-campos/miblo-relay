// The server's front page: shows this server's identity fingerprint (the one `miblo server set`
// shows; compare it with what your server printed when it started).
import "@/app/globals.css";
import "./fonts.css";

void fetch("/.well-known/miblo-relay.json")
  .then((r) => r.json())
  .then((d: { fingerprint?: string; version?: string }) => {
    const el = document.getElementById("fingerprint");
    if (el && d.fingerprint) el.textContent = d.fingerprint;
    const v = document.getElementById("version");
    if (v && d.version) v.textContent = d.version;
  })
  .catch(() => {});
