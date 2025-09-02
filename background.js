// Base de datos de patrones de phishing conocidos (optimizada con precompilación)
const PHISHING_PATTERNS = [
  /paypal-[a-z0-9]+\.com/i,
  /amazon-[a-z0-9]+\.net/i,
  /facebook-[a-z0-9]+\.org/i,
  /google-[a-z0-9]+\.net/i,
  /microsoft-[a-z0-9]+\.org/i,
  /apple-[a-z0-9]+\.net/i,
  /banking-[a-z0-9]+\.(com|net|org)/i,
  /secure-[a-z0-9]+\.(tk|ml|ga|cf)/i,
  /verify-[a-z0-9]+\.(com|net|org)/i,
  /support-[a-z0-9]+\.(com|net|org)/i,
  /account-[a-z0-9]+\.(tk|ml|ga|cf)/i,
];

// Base de datos de dominios de phishing conocidos
let PHISHING_DOMAINS = new Set();

// Palabras clave sospechosas
const SUSPICIOUS_KEYWORDS = new Set([
  "verify-account",
  "suspended-account",
  "urgent-action",
  "click-here-now",
  "limited-time",
  "act-now",
  "confirm-identity",
  "security-alert",
  "account-locked",
  "verify-now",
  "update-payment",
  "confirm-details",
  "reactivate-account",
  "login-verification",
]);

// Lista de dominios legítimos para comparación
const LEGITIMATE_DOMAINS = new Set([
  "paypal.com",
  "amazon.com",
  "facebook.com",
  "google.com",
  "microsoft.com",
  "apple.com",
  "gmail.com",
  "outlook.com",
  "youtube.com",
  "twitter.com",
  "instagram.com",
  "linkedin.com",
  "github.com",
  "stackoverflow.com",
  "reddit.com",
]);

// URL de la base de datos de phishing
const PHISHING_DB_URL = "https://phish.co.za/latest/ALL-phishing-domains.lst";

// Cache para resultados de análisis recientes
const ANALYSIS_CACHE = new Map();
const CACHE_MAX_SIZE = 1000;
const CACHE_TTL = 5 * 60 * 1000; // 5 minutos

// Estadísticas de la extensión
let extensionStats = {
  blocked: 0,
  scanned: 0,
  lastReset: Date.now(),
};

class PhishingDetector {
  constructor() {
    this.isInitialized = false;
    this.updateInProgress = false;
    this.init();
  }

  async init() {
    try {
      await this.loadExtensionStats();
      await this.loadPhishingDomains();
      this.initializeExtension();
      this.isInitialized = true;
      console.log("PhishingDetector initialized successfully");
    } catch (error) {
      console.error("Failed to initialize PhishingDetector:", error);
      // Inicializar con valores por defecto en caso de error
      this.initializeExtension();
      this.isInitialized = true;
    }
  }

  async loadExtensionStats() {
    try {
      const result = await chrome.storage.local.get(["extensionStats"]);
      if (result.extensionStats) {
        extensionStats = { ...extensionStats, ...result.extensionStats };
      }
    } catch (error) {
      console.error("Error loading extension stats:", error);
    }
  }

  async saveExtensionStats() {
    try {
      await chrome.storage.local.set({ extensionStats });
    } catch (error) {
      console.error("Error saving extension stats:", error);
    }
  }

  async loadPhishingDomains() {
    try {
      const result = await chrome.storage.local.get([
        "phishingDomains",
        "lastUpdate",
      ]);

      if (result.phishingDomains && Array.isArray(result.phishingDomains)) {
        PHISHING_DOMAINS = new Set(result.phishingDomains);
        console.log(
          `Loaded ${PHISHING_DOMAINS.size} phishing domains from storage`,
        );
      } else {
        await this.loadDefaultPhishingDomains();
      }

      // Verificar si necesita actualización (cada 24 horas)
      const lastUpdate = result.lastUpdate || 0;
      const now = Date.now();

      if (now - lastUpdate > 24 * 60 * 60 * 1000) {
        console.log("Phishing database needs update");
        this.setBadgeUpdateNeeded();

        // Programar actualización para no bloquear la inicialización
        setTimeout(() => this.autoUpdateDatabase(), 3000);
      }
    } catch (error) {
      console.error("Error loading phishing domains:", error);
      await this.loadDefaultPhishingDomains();
    }
  }

  async loadDefaultPhishingDomains() {
    const defaultDomains = [
      "00000000000000000000000000000000000000000.xyz",
      "000webhostapp.com",
      "weeblysite.com",
      "godaddysites.com",
      "pages.dev",
      "workers.dev",
      "appdomain.cloud",
      "tk",
      "ml",
      "ga",
      "cf", // Dominios gratuitos comúnmente usados para phishing
      "bit.ly",
      "tinyurl.com",
      "shortened.link", // Acortadores sospechosos
    ];

    PHISHING_DOMAINS = new Set(defaultDomains);
    await chrome.storage.local.set({
      phishingDomains: Array.from(PHISHING_DOMAINS),
      lastUpdate: Date.now(),
    });
    console.log("Loaded default phishing domains");
  }

  setBadgeUpdateNeeded() {
    chrome.action.setBadgeText({ text: "!" });
    chrome.action.setBadgeBackgroundColor({ color: "#FF9800" });
  }

  async autoUpdateDatabase() {
    if (this.updateInProgress) {
      console.log("Update already in progress, skipping...");
      return;
    }

    this.updateInProgress = true;

    try {
      console.log("Attempting auto-update from phish.co.za...");

      // Usar AbortController para timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15 segundos timeout

      const response = await fetch(PHISHING_DB_URL, {
        signal: controller.signal,
        headers: {
          "User-Agent": "Fisherman-Extension/1.0",
        },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const text = await response.text();
      const result = await this.updatePhishingDatabase(text);

      if (result.success) {
        console.log("Auto-update successful:", result.message);
        chrome.action.setBadgeText({ text: "" });

        // Mostrar notificación de actualización exitosa
        this.showNotification(
          "Base de datos actualizada",
          `${result.count} dominios maliciosos cargados automáticamente`,
        );
      } else {
        throw new Error(result.message);
      }
    } catch (error) {
      console.error("Auto-update failed:", error);
      this.setBadgeUpdateNeeded();
    } finally {
      this.updateInProgress = false;
    }
  }

  async updatePhishingDatabase(domainsText) {
    try {
      // Parsear el texto de dominios de manera más eficiente
      const domains = new Set();
      const lines = domainsText.split("\n");

      for (const line of lines) {
        const trimmed = line.trim().toLowerCase();
        if (
          trimmed && !trimmed.startsWith("#") && trimmed.includes(".") &&
          !trimmed.includes(" ")
        ) {
          domains.add(trimmed);
        }
      }

      if (domains.size === 0) {
        throw new Error("No se encontraron dominios válidos");
      }

      // Actualizar el Set
      PHISHING_DOMAINS = domains;

      // Guardar en storage
      await chrome.storage.local.set({
        phishingDomains: Array.from(PHISHING_DOMAINS),
        lastUpdate: Date.now(),
        domainCount: PHISHING_DOMAINS.size,
        sourceUrl: PHISHING_DB_URL,
      });

      console.log(
        `Updated phishing database with ${PHISHING_DOMAINS.size} domains`,
      );

      // Limpiar cache de análisis
      ANALYSIS_CACHE.clear();

      // Limpiar badge de actualización
      chrome.action.setBadgeText({ text: "" });

      return {
        success: true,
        count: PHISHING_DOMAINS.size,
        message:
          `Base de datos actualizada con ${PHISHING_DOMAINS.size} dominios`,
      };
    } catch (error) {
      console.error("Error updating phishing database:", error);
      return {
        success: false,
        message: "Error al actualizar la base de datos: " + error.message,
      };
    }
  }

  async forceUpdateDatabase() {
    chrome.action.setBadgeText({ text: "UPD" });
    chrome.action.setBadgeBackgroundColor({ color: "#2196F3" });

    return await this.autoUpdateDatabase();
  }

  showNotification(title, message) {
    try {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: `Fisherman - ${title}`,
        message: message,
      });
    } catch (error) {
      console.error("Error showing notification:", error);
    }
  }

  initializeExtension() {
    // Event listeners
    chrome.tabs.onUpdated.addListener(this.handleTabUpdate.bind(this));
    chrome.runtime.onMessage.addListener(this.handleMessage.bind(this));

    // Configurar badge inicial
    chrome.action.setBadgeBackgroundColor({ color: "#FF0000" });

    // Configurar alarma para actualizaciones diarias
    chrome.alarms.create("updatePhishingDB", {
      delayInMinutes: 1,
      periodInMinutes: 24 * 60,
    });

    // Configurar alarma para limpieza de cache
    chrome.alarms.create("cleanupCache", {
      delayInMinutes: 30,
      periodInMinutes: 30,
    });

    // Escuchar alarmas
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === "updatePhishingDB") {
        this.autoUpdateDatabase();
      } else if (alarm.name === "cleanupCache") {
        this.cleanupCache();
      }
    });
  }

  cleanupCache() {
    const now = Date.now();
    let cleaned = 0;

    for (const [key, value] of ANALYSIS_CACHE.entries()) {
      if (now - value.timestamp > CACHE_TTL) {
        ANALYSIS_CACHE.delete(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`Cleaned ${cleaned} expired cache entries`);
    }
  }

  handleTabUpdate(tabId, changeInfo, tab) {
    if (
      changeInfo.status === "complete" && tab.url && this.isValidUrl(tab.url)
    ) {
      this.analyzeURL(tab.url, tabId);
    }
  }

  isValidUrl(url) {
    return url &&
      !url.startsWith("chrome://") &&
      !url.startsWith("chrome-extension://") &&
      !url.startsWith("moz-extension://") &&
      !url.startsWith("about:") &&
      (url.startsWith("http://") || url.startsWith("https://"));
  }

  handleMessage(message, sender, sendResponse) {
    const handlers = {
      "CHECK_URL": () => {
        try {
          const result = this.analyzeURL(message.url, sender.tab?.id);
          sendResponse(result);
        } catch (error) {
          console.error("Error checking URL:", error);
          sendResponse({
            riskLevel: 0,
            warnings: [],
            isPhishing: false,
            isSuspicious: false,
            error: error.message,
          });
        }
      },

      "REPORT_SUSPICIOUS_CONTENT": () => {
        this.handleSuspiciousContent(message.data, sender.tab?.id);
        sendResponse({ status: "received" });
      },

      "UPDATE_PHISHING_DB": async () => {
        try {
          const result = await this.updatePhishingDatabase(message.domainsText);
          sendResponse(result);
        } catch (error) {
          sendResponse({ success: false, message: error.message });
        }
      },

      "FORCE_UPDATE_DB": async () => {
        try {
          const result = await this.forceUpdateDatabase();
          sendResponse(result);
        } catch (error) {
          sendResponse({ success: false, message: error.message });
        }
      },

      "GET_DB_INFO": async () => {
        try {
          const result = await chrome.storage.local.get([
            "domainCount",
            "lastUpdate",
            "sourceUrl",
          ]);
          sendResponse({
            count: result.domainCount || PHISHING_DOMAINS.size,
            lastUpdate: result.lastUpdate || 0,
            sourceUrl: result.sourceUrl || "Local",
          });
        } catch (error) {
          sendResponse({
            count: PHISHING_DOMAINS.size,
            lastUpdate: 0,
            sourceUrl: "Local",
            error: error.message,
          });
        }
      },

      "GET_STATS": () => {
        sendResponse(extensionStats);
      },

      "UPDATE_STATS": async () => {
        try {
          if (message.increment) {
            if (message.increment.blocked) {
              extensionStats.blocked += message.increment.blocked;
            }
            if (message.increment.scanned) {
              extensionStats.scanned += message.increment.scanned;
            }
          }
          await this.saveExtensionStats();
          sendResponse(extensionStats);
        } catch (error) {
          sendResponse({ error: error.message });
        }
      },
    };

    const handler = handlers[message.type];
    if (handler) {
      if (handler.constructor.name === "AsyncFunction") {
        handler();
        return true; // Indica respuesta asíncrona
      } else {
        handler();
      }
    } else {
      console.warn("Unknown message type:", message.type);
      sendResponse({ error: "Unknown message type" });
    }

    return false;
  }

  analyzeURL(url, tabId) {
    // Incrementar contador de páginas escaneadas
    extensionStats.scanned++;
    this.saveExtensionStats().catch(console.error);

    // Verificar cache primero
    const cacheKey = `${url}-${tabId || "no-tab"}`;
    const cachedResult = ANALYSIS_CACHE.get(cacheKey);

    if (cachedResult && (Date.now() - cachedResult.timestamp) < CACHE_TTL) {
      this.updateBadge(tabId, cachedResult);
      return cachedResult;
    }

    try {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();

      let riskLevel = 0;
      let warnings = [];

      // Verificar contra la base de datos de dominios conocidos
      if (this.checkKnownPhishingDomain(hostname)) {
        riskLevel += 5;
        warnings.push("Dominio encontrado en base de datos de phishing");
      }

      // Verificar patrones de phishing
      for (const pattern of PHISHING_PATTERNS) {
        if (pattern.test(hostname)) {
          riskLevel += 3;
          warnings.push("Patrón de dominio sospechoso detectado");
          break;
        }
      }

      // Verificar palabras clave sospechosas en la URL
      const fullUrl = url.toLowerCase();
      for (const keyword of SUSPICIOUS_KEYWORDS) {
        if (fullUrl.includes(keyword)) {
          riskLevel += 2;
          warnings.push("URL contiene términos sospechosos");
          break;
        }
      }

      // Verificar dominios similares a sitios legítimos
      const suspiciousDomain = this.checkSimilarDomains(hostname);
      if (suspiciousDomain) {
        riskLevel += 4;
        warnings.push(`Dominio similar a ${suspiciousDomain.legitimate}`);
      }

      // Verificar HTTPS
      if (
        urlObj.protocol !== "https:" && !hostname.includes("localhost") &&
        !hostname.includes("127.0.0.1")
      ) {
        riskLevel += 1;
        warnings.push("Conexión no segura (HTTP)");
      }

      // Verificar longitud sospechosa
      if (hostname.length > 50) {
        riskLevel += 1;
        warnings.push("Dominio excesivamente largo");
      }

      // Verificar subdominios múltiples
      const domainParts = hostname.split(".");
      if (domainParts.length > 4) {
        riskLevel += 1;
        warnings.push("Múltiples subdominios");
      }

      // Verificar caracteres sospechosos
      if (/[\u0400-\u04FF]/.test(hostname) || /xn--/.test(hostname)) {
        riskLevel += 2;
        warnings.push("Caracteres internacionales sospechosos");
      }

      const result = {
        riskLevel,
        warnings,
        isPhishing: riskLevel >= 4,
        isSuspicious: riskLevel >= 1,
        fromDatabase: this.checkKnownPhishingDomain(hostname),
        timestamp: Date.now(),
      };

      // Si es phishing, incrementar contador de bloqueados
      if (result.isPhishing) {
        extensionStats.blocked++;
        this.saveExtensionStats().catch(console.error);
      }

      // Actualizar cache
      if (ANALYSIS_CACHE.size >= CACHE_MAX_SIZE) {
        const oldestKey = ANALYSIS_CACHE.keys().next().value;
        ANALYSIS_CACHE.delete(oldestKey);
      }
      ANALYSIS_CACHE.set(cacheKey, result);

      // Actualizar badge
      this.updateBadge(tabId, result);

      return result;
    } catch (error) {
      console.error("Error analyzing URL:", error);
      return {
        riskLevel: 0,
        warnings: [],
        isPhishing: false,
        isSuspicious: false,
        timestamp: Date.now(),
        error: error.message,
      };
    }
  }

  checkKnownPhishingDomain(hostname) {
    // Verificar dominio exacto
    if (PHISHING_DOMAINS.has(hostname)) {
      return true;
    }

    // Verificar subdominios
    const parts = hostname.split(".");
    for (let i = 1; i < parts.length; i++) {
      const parentDomain = parts.slice(i).join(".");
      if (PHISHING_DOMAINS.has(parentDomain)) {
        return true;
      }
    }

    return false;
  }

  checkSimilarDomains(hostname) {
    if (LEGITIMATE_DOMAINS.has(hostname)) return null;

    for (const legitimate of LEGITIMATE_DOMAINS) {
      if (
        this.calculateSimilarity(hostname, legitimate) > 0.8 &&
        hostname !== legitimate
      ) {
        return { suspicious: hostname, legitimate };
      }
    }
    return null;
  }

  calculateSimilarity(str1, str2) {
    if (str1 === str2) return 1.0;

    const longer = str1.length > str2.length ? str1 : str2;
    const shorter = str1.length > str2.length ? str2 : str1;

    if (longer.length === 0) return 1.0;

    return (longer.length - this.editDistance(longer, shorter)) / longer.length;
  }

  editDistance(str1, str2) {
    if (str1.length === 0) return str2.length;
    if (str2.length === 0) return str1.length;

    const matrix = [];

    for (let i = 0; i <= str2.length; i++) {
      matrix[i] = [i];
    }

    for (let j = 0; j <= str1.length; j++) {
      matrix[0][j] = j;
    }

    for (let i = 1; i <= str2.length; i++) {
      for (let j = 1; j <= str1.length; j++) {
        if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // sustitución
            matrix[i][j - 1] + 1, // inserción
            matrix[i - 1][j] + 1, // eliminación
          );
        }
      }
    }

    return matrix[str2.length][str1.length];
  }

  updateBadge(tabId, result) {
    if (!tabId) return;

    try {
      if (result.isPhishing) {
        chrome.action.setBadgeText({ text: "!", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
      } else if (result.isSuspicious) {
        chrome.action.setBadgeText({ text: "?", tabId });
        chrome.action.setBadgeBackgroundColor({ color: "#FFA500", tabId });
      } else {
        chrome.action.setBadgeText({ text: "", tabId });
      }
    } catch (error) {
      console.error("Error updating badge:", error);
    }
  }

  handleSuspiciousContent(data, tabId) {
    console.log("Suspicious content detected:", data);
    // Aquí puedes implementar lógica adicional para manejar contenido sospechoso
    // Por ejemplo, registrar en analytics, reportar a un servidor, etc.
  }
}

// Inicializar el detector
const phishingDetector = new PhishingDetector();

// Exportar para uso en otros módulos si es necesario
if (typeof module !== "undefined" && module.exports) {
  module.exports = PhishingDetector;
}
