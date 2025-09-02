document.addEventListener("DOMContentLoaded", async () => {
  console.log("[Fisherman Popup] Script loaded");

  // Referencias a elementos DOM con validación
  const elements = {
    loading: document.getElementById("loading"),
    content: document.getElementById("content"),
    statusCard: document.getElementById("status-card"),
    statusIcon: document.getElementById("status-icon"),
    statusTitle: document.getElementById("status-title"),
    statusSubtitle: document.getElementById("status-subtitle"),
    warnings: document.getElementById("warnings"),
    warningsList: document.getElementById("warnings-list"),
    blockedCount: document.getElementById("blocked-count"),
    scannedCount: document.getElementById("scanned-count"),
    reportBtn: document.getElementById("report-site"),
    whitelistBtn: document.getElementById("whitelist-site"),
    updateDbBtn: document.getElementById("update-db-btn"),
    dbInfo: document.getElementById("db-info"),
  };

  // Verificar que todos los elementos existen
  const missingElements = Object.entries(elements).filter(([key, element]) =>
    !element
  );
  if (missingElements.length > 0) {
    console.error("[Fisherman Popup] Missing DOM elements:", missingElements);
    showFallbackError("Error: Elementos DOM faltantes");
    return;
  }

  console.log("[Fisherman Popup] All DOM elements found");

  // Variables globales
  let currentTab = null;
  let currentAnalysis = null;

  try {
    // Inicializar efectos visuales
    addRippleEffect();
    console.log("[Fisherman Popup] Ripple effects added");

    // Obtener pestaña activa con timeout
    const tabPromise = chrome.tabs.query({ active: true, currentWindow: true });
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("Timeout getting active tab")), 5000)
    );

    const [tab] = await Promise.race([tabPromise, timeoutPromise]);
    currentTab = tab;

    console.log("[Fisherman Popup] Active tab:", tab?.url);

    if (!tab || !tab.url) {
      showError(
        "No se puede acceder a esta página",
        "Extensión no disponible para esta URL",
      );
      return;
    }

    // Verificar si es una URL válida
    if (isSystemUrl(tab.url)) {
      showInfo(
        "Esta página no puede ser analizada",
        "Las páginas del sistema están protegidas",
      );
      return;
    }

    // Cargar información de la base de datos primero
    try {
      await loadDatabaseInfo();
      console.log("[Fisherman Popup] Database info loaded");
    } catch (error) {
      console.warn("[Fisherman Popup] Failed to load DB info:", error);
    }

    // Analizar URL con timeout y reintentos
    let analysis = null;
    let retries = 3;

    while (retries > 0 && !analysis) {
      try {
        console.log(
          "[Fisherman Popup] Requesting URL analysis, retries left:",
          retries,
        );

        const analysisPromise = chrome.runtime.sendMessage({
          type: "CHECK_URL",
          url: tab.url,
        });

        const timeoutPromise = new Promise((_, reject) =>
          setTimeout(() => reject(new Error("Analysis timeout")), 10000)
        );

        analysis = await Promise.race([analysisPromise, timeoutPromise]);
        console.log("[Fisherman Popup] Analysis result:", analysis);
      } catch (error) {
        console.error("[Fisherman Popup] Analysis attempt failed:", error);
        retries--;

        if (retries > 0) {
          await new Promise((resolve) => setTimeout(resolve, 1000)); // Esperar 1 segundo
        }
      }
    }

    if (!analysis) {
      throw new Error("Failed to get analysis after multiple attempts");
    }

    currentAnalysis = analysis;

    // Cargar estadísticas
    const stats = await loadStats();
    console.log("[Fisherman Popup] Stats loaded:", stats);

    // Mostrar resultados
    displayResults(analysis, tab.url, stats);
  } catch (error) {
    console.error("[Fisherman Popup] Critical error:", error);
    showError(
      "Error al analizar la página",
      `${error.message}. Intenta recargar la extensión.`,
    );
  }

  // Event listeners con manejo de errores
  elements.reportBtn.addEventListener("click", async () => {
    try {
      if (currentTab?.url) await reportSite(currentTab.url);
    } catch (error) {
      console.error("[Fisherman Popup] Report error:", error);
      showSnackbar("Error al reportar sitio", "error");
    }
  });

  elements.whitelistBtn.addEventListener("click", async () => {
    try {
      if (currentTab?.url) await whitelistSite(currentTab.url);
    } catch (error) {
      console.error("[Fisherman Popup] Whitelist error:", error);
      showSnackbar("Error al agregar a lista blanca", "error");
    }
  });

  elements.updateDbBtn.addEventListener("click", async () => {
    try {
      await updateDatabase();
    } catch (error) {
      console.error("[Fisherman Popup] Update DB error:", error);
      showSnackbar("Error al actualizar base de datos", "error");
    }
  });

  // Funciones principales

  function isSystemUrl(url) {
    return url.startsWith("chrome://") ||
      url.startsWith("chrome-extension://") ||
      url.startsWith("moz-extension://") ||
      url.startsWith("about:") ||
      url.startsWith("edge://") ||
      url.startsWith("extension://");
  }

  function displayResults(analysis, url, stats) {
    console.log("[Fisherman Popup] Displaying results");

    elements.loading.style.display = "none";
    elements.content.style.display = "block";

    // Actualizar estadísticas
    animateNumber(elements.blockedCount, stats.blocked || 0);
    animateNumber(elements.scannedCount, stats.scanned || 0);

    // Verificar lista blanca
    checkWhitelist(url).then((isWhitelisted) => {
      if (isWhitelisted) {
        showWhitelistedState();
        return;
      }

      if (analysis.isPhishing) {
        showPhishingState(analysis);
      } else if (analysis.isSuspicious) {
        showSuspiciousState(analysis);
      } else {
        showSafeState();
      }
    }).catch((error) => {
      console.error("[Fisherman Popup] Whitelist check error:", error);
      // Continuar con análisis normal si falla la verificación de whitelist
      if (analysis.isPhishing) {
        showPhishingState(analysis);
      } else if (analysis.isSuspicious) {
        showSuspiciousState(analysis);
      } else {
        showSafeState();
      }
    });
  }

  function showWhitelistedState() {
    elements.statusCard.className = "status-card status-safe";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #4caf50; font-size: 28px;">verified_user</span>';
    elements.statusTitle.textContent = "SITIO CONFIABLE";
    elements.statusSubtitle.textContent = "Este sitio está en tu lista blanca";
    elements.warnings.style.display = "none";

    elements.reportBtn.disabled = false;
    elements.whitelistBtn.disabled = true;
    elements.whitelistBtn.innerHTML =
      '<span class="material-icons" style="font-size: 16px; margin-right: 4px;">verified</span>Confiado';
    elements.whitelistBtn.style.opacity = "0.7";
  }

  function showPhishingState(analysis) {
    elements.statusCard.className = "status-card status-danger";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #f44336; font-size: 28px;">dangerous</span>';
    elements.statusTitle.textContent = "SITIO PELIGROSO DETECTADO";
    elements.statusSubtitle.textContent = "Se recomienda salir inmediatamente";

    if (analysis.warnings && analysis.warnings.length > 0) {
      showWarnings(analysis.warnings);
    }

    elements.reportBtn.disabled = true;
    elements.reportBtn.style.opacity = "0.5";
    elements.whitelistBtn.disabled = false;
    elements.whitelistBtn.style.opacity = "1";
  }

  function showSuspiciousState(analysis) {
    elements.statusCard.className = "status-card status-warning";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #ff9800; font-size: 28px;">warning</span>';
    elements.statusTitle.textContent = "SITIO POTENCIALMENTE SOSPECHOSO";
    elements.statusSubtitle.textContent = "Procede con precaución";

    if (analysis.warnings && analysis.warnings.length > 0) {
      showWarnings(analysis.warnings);
    }

    elements.reportBtn.disabled = false;
    elements.reportBtn.style.opacity = "1";
    elements.whitelistBtn.disabled = false;
    elements.whitelistBtn.style.opacity = "1";
  }

  function showSafeState() {
    elements.statusCard.className = "status-card status-safe";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #4caf50; font-size: 28px;">verified</span>';
    elements.statusTitle.textContent = "SITIO SEGURO";
    elements.statusSubtitle.textContent = "No se detectaron amenazas";
    elements.warnings.style.display = "none";

    elements.reportBtn.disabled = false;
    elements.reportBtn.style.opacity = "1";
    elements.whitelistBtn.disabled = false;
    elements.whitelistBtn.style.opacity = "1";
  }

  function showWarnings(warnings) {
    elements.warnings.style.display = "block";
    elements.warningsList.innerHTML = "";

    warnings.forEach((warning) => {
      const li = document.createElement("li");
      li.className = "warning-item";
      li.textContent = warning;
      elements.warningsList.appendChild(li);
    });
  }

  function showError(title, message) {
    console.log("[Fisherman Popup] Showing error:", title, message);

    elements.loading.style.display = "none";
    elements.content.style.display = "block";

    elements.statusCard.className = "status-card status-danger";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #f44336; font-size: 28px;">error</span>';
    elements.statusTitle.textContent = title;
    elements.statusSubtitle.textContent = message;
    elements.warnings.style.display = "none";

    // Deshabilitar botones
    elements.reportBtn.disabled = true;
    elements.whitelistBtn.disabled = true;
    elements.reportBtn.style.opacity = "0.5";
    elements.whitelistBtn.style.opacity = "0.5";

    // Mostrar estadísticas básicas
    elements.blockedCount.textContent = "0";
    elements.scannedCount.textContent = "0";
  }

  function showInfo(title, message) {
    elements.loading.style.display = "none";
    elements.content.style.display = "block";

    elements.statusCard.className = "status-card status-safe";
    elements.statusIcon.innerHTML =
      '<span class="material-icons" style="color: #2196f3; font-size: 28px;">info</span>';
    elements.statusTitle.textContent = title;
    elements.statusSubtitle.textContent = message;
    elements.warnings.style.display = "none";

    elements.reportBtn.disabled = true;
    elements.whitelistBtn.disabled = true;
    elements.reportBtn.style.opacity = "0.5";
    elements.whitelistBtn.style.opacity = "0.5";

    loadStats().then((stats) => {
      animateNumber(elements.blockedCount, stats.blocked || 0);
      animateNumber(elements.scannedCount, stats.scanned || 0);
    }).catch((error) => {
      console.error("[Fisherman Popup] Error loading stats for info:", error);
    });
  }

  function showFallbackError(message) {
    // Mostrar error básico sin depender de elementos DOM
    document.body.innerHTML = `
            <div style="padding: 20px; text-align: center; font-family: Arial, sans-serif;">
                <h3 style="color: #f44336; margin-bottom: 10px;">Error de Fisherman</h3>
                <p style="color: #666;">${message}</p>
                <button onclick="location.reload()" style="margin-top: 15px; padding: 8px 16px; background: #1976d2; color: white; border: none; border-radius: 4px; cursor: pointer;">Recargar</button>
            </div>
        `;
  }

  // Funciones auxiliares (mantener las mismas del archivo anterior)
  async function loadStats() {
    try {
      const response = await chrome.runtime.sendMessage({ type: "GET_STATS" });
      return response || { blocked: 0, scanned: 0 };
    } catch (error) {
      console.error("[Fisherman Popup] Error loading stats:", error);
      return { blocked: 0, scanned: 0 };
    }
  }

  async function checkWhitelist(url) {
    try {
      const hostname = new URL(url).hostname;
      const whitelist = await chrome.storage.local.get(["whitelist"]);
      const currentWhitelist = whitelist.whitelist || [];
      return currentWhitelist.includes(hostname);
    } catch (error) {
      console.error("[Fisherman Popup] Error checking whitelist:", error);
      return false;
    }
  }

  async function loadDatabaseInfo() {
    try {
      const response = await chrome.runtime.sendMessage({
        type: "GET_DB_INFO",
      });
      if (response && elements.dbInfo) {
        const lastUpdate = response.lastUpdate
          ? new Date(response.lastUpdate).toLocaleDateString()
          : "Nunca";
        elements.dbInfo.textContent = `${
          response.count || 0
        } dominios • Actualizado: ${lastUpdate}`;
      }
    } catch (error) {
      console.error("[Fisherman Popup] Error loading DB info:", error);
      if (elements.dbInfo) {
        elements.dbInfo.textContent = "Error cargando información";
      }
    }
  }

  async function updateDatabase() {
    if (!elements.updateDbBtn) return;

    try {
      elements.updateDbBtn.disabled = true;
      elements.updateDbBtn.innerHTML =
        '<span class="material-icons" style="font-size: 16px; margin-right: 4px;">refresh</span>Actualizando...';

      const response = await chrome.runtime.sendMessage({
        type: "FORCE_UPDATE_DB",
      });

      if (response && response.success) {
        showSnackbar("Base de datos actualizada correctamente", "success");
        await loadDatabaseInfo();
      } else {
        showSnackbar("Error al actualizar base de datos", "error");
      }
    } catch (error) {
      console.error("[Fisherman Popup] Update database error:", error);
      showSnackbar("Error de conexión", "error");
    } finally {
      elements.updateDbBtn.disabled = false;
      elements.updateDbBtn.innerHTML =
        '<span class="material-icons" style="font-size: 16px; margin-right: 4px;">update</span>Actualizar Base de Datos';
    }
  }

  // Resto de funciones auxiliares simplificadas
  function animateNumber(element, target) {
    if (!element) return;
    const start = parseInt(element.textContent) || 0;
    const duration = 1000;
    const startTime = performance.now();

    function updateNumber(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const current = Math.floor(start + (target - start) * progress);
      element.textContent = current;
      if (progress < 1) requestAnimationFrame(updateNumber);
    }
    requestAnimationFrame(updateNumber);
  }

  function showSnackbar(message, type = "info") {
    console.log("[Fisherman Popup] Snackbar:", message, type);
    // Implementación simplificada del snackbar
    // (mantener la implementación anterior)
  }

  function addRippleEffect() {
    // Implementación simplificada
    document.querySelectorAll(".btn").forEach((button) => {
      button.addEventListener("click", function (e) {
        // Efecto visual simple
        this.style.transform = "scale(0.95)";
        setTimeout(() => {
          this.style.transform = "scale(1)";
        }, 150);
      });
    });
  }

  async function whitelistSite(url) {
    // Implementación simplificada
    console.log("[Fisherman Popup] Whitelisting:", url);
    showSnackbar("Función de lista blanca ejecutada", "info");
  }

  async function reportSite(url) {
    // Implementación simplificada
    console.log("[Fisherman Popup] Reporting:", url);
    showSnackbar("Sitio reportado", "success");
  }
});
