// Content script para detección en tiempo real de phishing
(function() {
    'use strict';

    // Evitar múltiples inyecciones
    if (window.fishermanContentLoaded) {
        return;
    }
    window.fishermanContentLoaded = true;

    // Configuración
    const CONFIG = {
        checkInterval: 2000, // Verificar cada 2 segundos
        maxChecks: 30, // Máximo 30 verificaciones (1 minuto)
        suspiciousFormThreshold: 3, // Número de campos sospechosos para alertar
        suspiciousLinkThreshold: 5 // Número de links sospechosos para alertar
    };

    // Patrones sospechosos para detectar en el contenido
    const SUSPICIOUS_PATTERNS = {
        // Texto sospechoso
        text: [
            /verify.*account.*immediately/i,
            /account.*suspended.*click/i,
            /urgent.*action.*required/i,
            /confirm.*identity.*now/i,
            /update.*payment.*information/i,
            /security.*alert.*verify/i,
            /login.*expired.*reactivate/i,
            /limited.*time.*offer/i,
            /act.*now.*before/i,
            /congratulations.*winner/i,
            /claim.*prize.*now/i,
            /tax.*refund.*pending/i
        ],
        
        // URLs sospechosas en links
        urls: [
            /bit\.ly|tinyurl|shortened/i,
            /[a-z0-9]{20,}\.tk|\.ml|\.ga|\.cf/i,
            /paypal-[a-z0-9]+\.(com|net|org)/i,
            /amazon-[a-z0-9]+\.net/i,
            /facebook-[a-z0-9]+\.org/i,
            /google-[a-z0-9]+\.net/i,
            /microsoft-[a-z0-9]+\.org/i,
            /apple-[a-z0-9]+\.net/i
        ],
        
        // Campos de formulario sospechosos
        formFields: [
            /password|pwd|pass/i,
            /credit.*card|cc.*number|card.*number/i,
            /social.*security|ssn/i,
            /bank.*account|routing.*number/i,
            /pin.*code|pin.*number/i,
            /security.*code|cvv|cvc/i
        ]
    };

    // Palabras clave legítimas que pueden aparecer en sitios reales
    const LEGITIMATE_KEYWORDS = [
        'official', 'secure', 'verified', 'trusted', 'authentic'
    ];

    // Estado del análisis
    let analysisState = {
        checkCount: 0,
        lastAnalysis: null,
        observer: null,
        isAnalyzing: false,
        suspiciousElements: new Set()
    };

    // Inicializar el content script
    function init() {
        console.log('[Fisherman] Content script loaded for:', window.location.href);
        
        // Esperar a que la página esté lista
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', startAnalysis);
        } else {
            startAnalysis();
        }
    }

    function startAnalysis() {
        // Análisis inicial
        performAnalysis();
        
        // Configurar observador para cambios dinámicos
        setupMutationObserver();
        
        // Análisis periódico para contenido dinámico
        setupPeriodicAnalysis();
        
        // Interceptar formularios
        interceptForms();
    }

    function performAnalysis() {
        if (analysisState.isAnalyzing) return;
        
        analysisState.isAnalyzing = true;
        analysisState.checkCount++;

        try {
            const analysis = {
                timestamp: Date.now(),
                url: window.location.href,
                domain: window.location.hostname,
                suspiciousText: analyzeSuspiciousText(),
                suspiciousLinks: analyzeSuspiciousLinks(),
                suspiciousForms: analyzeSuspiciousForms(),
                metaAnalysis: analyzeMetaData(),
                visualCues: analyzeVisualCues()
            };

            const riskScore = calculateRiskScore(analysis);
            analysis.riskScore = riskScore;
            analysis.isHighRisk = riskScore >= 70;
            analysis.isMediumRisk = riskScore >= 40;

            // Enviar resultado al background script
            if (analysis.isHighRisk || analysis.isMediumRisk) {
                reportSuspiciousContent(analysis);
            }

            analysisState.lastAnalysis = analysis;
            
        } catch (error) {
            console.error('[Fisherman] Error during analysis:', error);
        } finally {
            analysisState.isAnalyzing = false;
        }
    }

    function analyzeSuspiciousText() {
        const suspiciousTexts = [];
        const textContent = document.body ? document.body.innerText.toLowerCase() : '';
        
        SUSPICIOUS_PATTERNS.text.forEach(pattern => {
            const matches = textContent.match(pattern);
            if (matches) {
                suspiciousTexts.push({
                    pattern: pattern.toString(),
                    match: matches[0],
                    context: getContext(matches[0], textContent)
                });
            }
        });

        // Buscar elementos con texto sospechoso
        const textElements = document.querySelectorAll('p, div, span, h1, h2, h3, h4, h5, h6, button');
        textElements.forEach(element => {
            const text = element.innerText.toLowerCase();
            SUSPICIOUS_PATTERNS.text.forEach(pattern => {
                if (pattern.test(text)) {
                    analysisState.suspiciousElements.add(element);
                    highlightSuspiciousElement(element, 'text');
                }
            });
        });

        return suspiciousTexts;
    }

    function analyzeSuspiciousLinks() {
        const suspiciousLinks = [];
        const links = document.querySelectorAll('a[href]');
        
        links.forEach(link => {
            const href = link.href.toLowerCase();
            const text = link.innerText.toLowerCase();
            
            SUSPICIOUS_PATTERNS.urls.forEach(pattern => {
                if (pattern.test(href)) {
                    suspiciousLinks.push({
                        url: link.href,
                        text: link.innerText,
                        pattern: pattern.toString()
                    });
                    
                    analysisState.suspiciousElements.add(link);
                    highlightSuspiciousElement(link, 'link');
                }
            });

            // Verificar si el texto del enlace no coincide con el destino
            if (isDeceptiveLink(link)) {
                suspiciousLinks.push({
                    url: link.href,
                    text: link.innerText,
                    reason: 'deceptive_text'
                });
                
                analysisState.suspiciousElements.add(link);
                highlightSuspiciousElement(link, 'deceptive');
            }
        });

        return suspiciousLinks;
    }

    function analyzeSuspiciousForms() {
        const suspiciousForms = [];
        const forms = document.querySelectorAll('form');
        
        forms.forEach(form => {
            const inputs = form.querySelectorAll('input, textarea, select');
            let suspiciousFields = 0;
            const fieldTypes = [];
            
            inputs.forEach(input => {
                const name = (input.name || '').toLowerCase();
                const id = (input.id || '').toLowerCase();
                const placeholder = (input.placeholder || '').toLowerCase();
                const label = findAssociatedLabel(input);
                
                const fieldText = `${name} ${id} ${placeholder} ${label}`.toLowerCase();
                
                SUSPICIOUS_PATTERNS.formFields.forEach(pattern => {
                    if (pattern.test(fieldText)) {
                        suspiciousFields++;
                        fieldTypes.push({
                            element: input,
                            type: input.type,
                            pattern: pattern.toString(),
                            text: fieldText.trim()
                        });
                        
                        analysisState.suspiciousElements.add(input);
                        highlightSuspiciousElement(input, 'form-field');
                    }
                });
            });
            
            if (suspiciousFields >= CONFIG.suspiciousFormThreshold) {
                suspiciousForms.push({
                    form: form,
                    suspiciousFieldCount: suspiciousFields,
                    fieldTypes: fieldTypes,
                    action: form.action,
                    method: form.method
                });
                
                analysisState.suspiciousElements.add(form);
                highlightSuspiciousElement(form, 'form');
            }
        });

        return suspiciousForms;
    }

    function analyzeMetaData() {
        const meta = {
            title: document.title,
            description: '',
            favicon: '',
            ssl: window.location.protocol === 'https:'
        };

        // Descripción meta
        const descMeta = document.querySelector('meta[name="description"]');
        if (descMeta) {
            meta.description = descMeta.content;
        }

        // Favicon
        const faviconLink = document.querySelector('link[rel="icon"], link[rel="shortcut icon"]');
        if (faviconLink) {
            meta.favicon = faviconLink.href;
        }

        // Verificar si el título coincide con el dominio esperado
        const title = meta.title.toLowerCase();
        const hostname = window.location.hostname.toLowerCase();
        
        meta.titleDomainMismatch = checkTitleDomainMismatch(title, hostname);

        return meta;
    }

    function analyzeVisualCues() {
        const cues = {
            urgencyIndicators: 0,
            trustSymbols: 0,
            popups: 0,
            redirects: 0
        };

        // Buscar indicadores de urgencia visual
        const urgentElements = document.querySelectorAll('[style*="red"], [style*="blink"], [class*="urgent"], [class*="warning"]');
        cues.urgencyIndicators = urgentElements.length;

        // Símbolos de confianza falsos
        const trustElements = document.querySelectorAll('img[src*="ssl"], img[src*="secure"], img[src*="verified"], img[src*="trust"]');
        cues.trustSymbols = trustElements.length;

        // Popups sospechosos
        const popupElements = document.querySelectorAll('[style*="position:fixed"], [style*="position: fixed"], .modal, .popup');
        cues.popups = popupElements.length;

        return cues;
    }

    function calculateRiskScore(analysis) {
        let score = 0;

        // Texto sospechoso (30 puntos máximo)
        score += Math.min(analysis.suspiciousText.length * 10, 30);

        // Enlaces sospechosos (25 puntos máximo)
        score += Math.min(analysis.suspiciousLinks.length * 5, 25);

        // Formularios sospechosos (35 puntos máximo)
        score += Math.min(analysis.suspiciousForms.length * 15, 35);

        // Sin SSL (10 puntos)
        if (!analysis.metaAnalysis.ssl) {
            score += 10;
        }

        // Discrepancia título-dominio (15 puntos)
        if (analysis.metaAnalysis.titleDomainMismatch) {
            score += 15;
        }

        // Indicadores visuales (10 puntos máximo)
        score += Math.min(analysis.visualCues.urgencyIndicators * 2, 10);

        return Math.min(score, 100);
    }

    function setupMutationObserver() {
        if (analysisState.observer) {
            analysisState.observer.disconnect();
        }

        analysisState.observer = new MutationObserver((mutations) => {
            let shouldAnalyze = false;
            
            mutations.forEach(mutation => {
                if (mutation.type === 'childList' && mutation.addedNodes.length > 0) {
                    mutation.addedNodes.forEach(node => {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            // Verificar si se agregaron formularios o enlaces
                            if (node.tagName === 'FORM' || node.tagName === 'A' || 
                                node.querySelector && (node.querySelector('form') || node.querySelector('a'))) {
                                shouldAnalyze = true;
                            }
                        }
                    });
                }
            });
            
            if (shouldAnalyze) {
                setTimeout(performAnalysis, 500); // Debounce
            }
        });

        analysisState.observer.observe(document.body, {
            childList: true,
            subtree: true
        });
    }

    function setupPeriodicAnalysis() {
        const interval = setInterval(() => {
            if (analysisState.checkCount >= CONFIG.maxChecks) {
                clearInterval(interval);
                return;
            }
            
            performAnalysis();
        }, CONFIG.checkInterval);
    }

    function interceptForms() {
        document.addEventListener('submit', (event) => {
            const form = event.target;
            if (analysisState.suspiciousElements.has(form)) {
                const confirmed = confirm(
                    '⚠️ ADVERTENCIA DE FISHERMAN ⚠️\n\n' +
                    'Este formulario contiene campos sospechosos que podrían ser utilizados para robar información personal.\n\n' +
                    '¿Estás seguro de que quieres continuar?'
                );
                
                if (!confirmed) {
                    event.preventDefault();
                    event.stopPropagation();
                    return false;
                }
            }
        }, true);
    }

    function highlightSuspiciousElement(element, type) {
        if (!element || element.dataset.fishermanHighlighted) return;

        const colors = {
            'text': '#ff9800',
            'link': '#f44336', 
            'form': '#e91e63',
            'form-field': '#9c27b0',
            'deceptive': '#ff5722'
        };

        const originalStyle = element.style.cssText;
        element.dataset.fishermanOriginalStyle = originalStyle;
        element.dataset.fishermanHighlighted = 'true';
        
        element.style.cssText += `
            outline: 2px dashed ${colors[type]} !important;
            outline-offset: 2px !important;
            position: relative !important;
        `;

        // Agregar tooltip
        const tooltip = document.createElement('div');
        tooltip.className = 'fisherman-tooltip';
        tooltip.textContent = `⚠️ Elemento sospechoso detectado`;
        tooltip.style.cssText = `
            position: absolute !important;
            top: -30px !important;
            left: 0 !important;
            background: ${colors[type]} !important;
            color: white !important;
            padding: 4px 8px !important;
            border-radius: 4px !important;
            font-size: 12px !important;
            z-index: 10000 !important;
            opacity: 0 !important;
            transition: opacity 0.3s !important;
        `;

        element.appendChild(tooltip);

        element.addEventListener('mouseenter', () => {
            tooltip.style.opacity = '1';
        });

        element.addEventListener('mouseleave', () => {
            tooltip.style.opacity = '0';
        });
    }

    function reportSuspiciousContent(analysis) {
        try {
            chrome.runtime.sendMessage({
                type: 'REPORT_SUSPICIOUS_CONTENT',
                data: {
                    url: analysis.url,
                    domain: analysis.domain,
                    riskScore: analysis.riskScore,
                    suspiciousText: analysis.suspiciousText.length,
                    suspiciousLinks: analysis.suspiciousLinks.length,
                    suspiciousForms: analysis.suspiciousForms.length,
                    timestamp: analysis.timestamp,
                    userAgent: navigator.userAgent
                }
            });
        } catch (error) {
            console.error('[Fisherman] Error reporting suspicious content:', error);
        }
    }

    // Funciones auxiliares

    function getContext(match, fullText, contextLength = 50) {
        const index = fullText.indexOf(match.toLowerCase());
        if (index === -1) return match;
        
        const start = Math.max(0, index - contextLength);
        const end = Math.min(fullText.length, index + match.length + contextLength);
        
        return fullText.substring(start, end);
    }

    function isDeceptiveLink(link) {
        const text = link.innerText.toLowerCase().trim();
        const href = link.href.toLowerCase();
        
        // Verificar si el texto sugiere un sitio pero la URL es otra
        LEGITIMATE_KEYWORDS.forEach(keyword => {
            if (text.includes(keyword)) {
                const hostname = new URL(href).hostname;
                // Si el texto sugiere legitimidad pero el dominio es sospechoso
                if (!hostname.includes(keyword)) {
                    return true;
                }
            }
        });

        return false;
    }

    function findAssociatedLabel(input) {
        if (input.id) {
            const label = document.querySelector(`label[for="${input.id}"]`);
            if (label) return label.innerText;
        }
        
        const parentLabel = input.closest('label');
        if (parentLabel) return parentLabel.innerText;
        
        return '';
    }

    function checkTitleDomainMismatch(title, hostname) {
        const commonServices = ['paypal', 'amazon', 'facebook', 'google', 'microsoft', 'apple', 'ebay', 'netflix'];
        
        for (const service of commonServices) {
            if (title.includes(service) && !hostname.includes(service)) {
                return true;
            }
        }
        
        return false;
    }

    // Cleanup al descargar la página
    window.addEventListener('beforeunload', () => {
        if (analysisState.observer) {
            analysisState.observer.disconnect();
        }
        
        // Remover highlights
        analysisState.suspiciousElements.forEach(element => {
            if (element.dataset.fishermanHighlighted) {
                element.style.cssText = element.dataset.fishermanOriginalStyle || '';
                delete element.dataset.fishermanHighlighted;
                delete element.dataset.fishermanOriginalStyle;
                
                const tooltip = element.querySelector('.fisherman-tooltip');
                if (tooltip) {
                    tooltip.remove();
                }
            }
        });
    });

    // Inicializar
    init();

})();
