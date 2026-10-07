// The relay suite on workerd through Miniflare (the Cloudflare deploy).
import { relaySuite } from "./suite";
import { workerdHarness } from "./harness";

relaySuite(workerdHarness);
