// The relay suite on the Node runtime (the Docker deploy).
import { relaySuite } from "./suite";
import { nodeHarness } from "./harness";

relaySuite(nodeHarness);
