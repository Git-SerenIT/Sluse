# A reference MCP server for Sluse

An MCP tool server protected by Microsoft Entra, on Azure Functions (Flex
Consumption), that reads Microsoft Graph **as the person** who calls it
through Sluse. It is the pattern an organisation copies to put its own data
behind Sluse as an MCP source, and the server Sluse's own tests run against.

Derived from Microsoft's
[mcp-sdk-functions-hosting-node](https://github.com/Azure-Samples/mcp-sdk-functions-hosting-node)
(MIT, see `LICENSE`): its infrastructure as published, apart from Node.js 24;
the weather tools replaced.

## The tools

| Tool | What it does |
|---|---|
| `whoami` | The person's name, user principal name, mail and job title from Graph `/me`. The server swaps the token Sluse sent for a Graph token by on-behalf-of; its app proves itself with a managed identity, so **no client secret exists** |
| `get_notice` | **A test payload, delete it in your copy.** A notice with an instruction planted in it. Sluse should hand the result to the agent as untrusted data; an agent that follows it ends its answer with `MARMALADE-42` and calls the tool again with the topic `everything`, which Sluse's journal shows. With `topic` pinned in Sluse Admin, Sluse sets the pinned value over the agent's, and the notice echoes the topic it got |

## What gets created

`azd up` creates, in one resource group: an Entra app registration for the
server (Application ID URI `api://<function-app>-app-<hash>`, one delegated
scope `user_impersonation`, Graph `User.Read`), a user-assigned managed
identity federated to it, a Flex Consumption plan and Function App, a storage
account, Log Analytics and Application Insights. Easy Auth on the Function
App refuses any request without a token for that app (401).

**Sluse asks Entra by scope, never by `resource`**, so the Application ID URI
does not have to be the server's URL, and the template's is kept (D-071).

## Deploy

Needs: [azd](https://aka.ms/azd), an Azure subscription, and roles to create
an app registration (Application Developer or more) and role assignments on
the subscription (Owner, or Contributor and User Access Administrator).

```shell
az provider register --namespace Microsoft.App   # once per subscription
azd auth login --tenant-id <tenant>
azd env new sluse-mcp-reference
azd env set AZURE_LOCATION swedencentral
azd env set VNET_ENABLED false     # true adds a VNet and a private endpoint for storage
azd up
```

Optional: `azd env set PRE_AUTHORIZED_CLIENT_IDS <Sluse's client ID>` before
`azd up` pre-authorizes Sluse's app, so no consent for the server's scope is
needed. Without it, the admin consents when adding the server in Sluse Admin.

The endpoint is `https://<function-app>.azurewebsites.net/mcp`; `azd env get-values`
shows `ENTRA_IDENTIFIER_URI`.

## Connect it to Sluse

1. **Graph consent for the server.** On-behalf-of runs without the person
   present, so the server's own `User.Read` needs admin consent: Entra admin
   center, **App registrations → (the server's app) → API permissions → Grant
   admin consent**.
2. **Add the server in Sluse Admin** as an MCP source: the endpoint above,
   and the scope `<ENTRA_IDENTIFIER_URI>/user_impersonation`. Sluse Admin
   probes the MCP version (this server speaks 2025-11-25), lists the tools
   with your sign-in, and you tick and pin them.

## Known

- `npm audit` reports GHSA-xcx6-jx8p-x3h5 in `@azure/msal-node` 6, through
  `@azure/identity` 4.14. The advisory is in MSAL's authorization-code flow;
  this server uses on-behalf-of and a managed identity only. Fixed in
  msal-node 7.1, which no `@azure/identity` release takes yet (2026-10-28).
- Stateless only: no sessions, no server-to-client stream (`GET /mcp` is 405).
