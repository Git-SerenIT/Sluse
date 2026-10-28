// Derived from Azure-Samples/mcp-sdk-functions-hosting-node (MIT, Microsoft
// Corporation; see LICENSE). Changed for Sluse: a server per request, as the
// sample's own comment says but its code did not do; the consent page removed
// (consent is the admin's, in Sluse Admin).

import express from "express";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { createServer } from "./server.js";

const app = express();
app.use(express.json());

// Stateless: a transport and a server for each POST, so concurrent clients'
// request ids cannot collide.
app.post("/mcp", async (req, res) => {
  try {
    const server = createServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      transport.close();
      server.close();
    });
    await server.connect(transport);
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    console.error("Error handling MCP request:", error);
    if (!res.headersSent) {
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
    }
  }
});

// No SSE stream and no sessions in stateless mode.
const notAllowed = (_req: express.Request, res: express.Response) => {
  res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed." }, id: null });
};
app.get("/mcp", notAllowed);
app.delete("/mcp", notAllowed);

const PORT = process.env.PORT || 3000;
app.listen(PORT, (error?: Error) => {
  if (error) {
    console.error("Failed to start server:", error);
    process.exit(1);
  }
  console.log(`MCP endpoint: http://localhost:${PORT}/mcp`);
});
