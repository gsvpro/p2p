import express from "express";
import { createServer as createViteServer } from "vite";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Middleware for proxying payloads
  app.use(express.json());
  app.use(express.raw({ type: "application/octet-stream", limit: "2mb" }));

  // API routes
  app.get("/api/health", (req, res) => {
    res.json({ status: "ok" });
  });

  /**
   * Pkarr Proxy to bypass CORS
   * Maps /api/pkarr-proxy/relay.host/id to https://relay.host/id
   */
  app.all("/api/pkarr-proxy/*", async (req, res) => {
    try {
      const pathParts = req.params[0].split("/");
      const targetHost = pathParts[0];
      const targetPath = pathParts.slice(1).join("/");
      
      const targetUrl = `https://${targetHost}/${targetPath}${req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : ""}`;
      
      console.log(`Proxying ${req.method} request to: ${targetUrl}`);

      const response = await fetch(targetUrl, {
        method: req.method,
        headers: {
          "Content-Type": req.headers["content-type"] || "application/octet-stream",
        },
        body: ["POST", "PUT"].includes(req.method) ? req.body : undefined,
      });

      res.status(response.status);
      
      // Copy headers that might be needed, but skip CORS ones as we are the origin now
      const headersToCopy = ["content-type", "cache-control", "last-modified"];
      headersToCopy.forEach(h => {
        const val = response.headers.get(h);
        if (val) res.setHeader(h, val);
      });

      const data = await response.arrayBuffer();
      res.send(Buffer.from(data));
    } catch (error) {
      console.error("Pkarr Proxy Error:", error);
      res.status(500).json({ error: "Failed to proxy Pkarr request" });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Development server running at http://localhost:${PORT}`);
  });
}

startServer();
