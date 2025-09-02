document.addEventListener('DOMContentLoaded', () => {
    const domainsTextarea = document.getElementById('domains-textarea');
    const fileInput = document.getElementById('file-input');
    const updateBtn = document.getElementById('update-btn');
    const clearBtn = document.getElementById('clear-btn');
    const sampleBtn = document.getElementById('sample-btn');
    const progressContainer = document.getElementById('progress-container');
    const progressFill = document.getElementById('progress-fill');
    const alertContainer = document.getElementById('alert-container');
    const currentDomainsEl = document.getElementById('current-domains');
    const lastUpdateEl = document.getElementById('last-update');

    // Cargar información actual
    loadCurrentStats();

    // Event listeners
    fileInput.addEventListener('change', handleFileInput);
    updateBtn.addEventListener('click', updateDatabase);
    clearBtn.addEventListener('click', clearTextarea);
    sampleBtn.addEventListener('click', loadSampleData);

    async function loadCurrentStats() {
        try {
            const response = await chrome.runtime.sendMessage({ type: 'GET_DB_INFO' });
            
            currentDomainsEl.textContent = response.count || 0;
            
            if (response.lastUpdate && response.lastUpdate > 0) {
                const date = new Date(response.lastUpdate);
                lastUpdateEl.textContent = date.toLocaleDateString('es-ES');
                lastUpdateEl.style.fontSize = '20px';
            } else {
                lastUpdateEl.textContent = 'Nunca';
            }
        } catch (error) {
            console.error('Error loading current stats:', error);
            showAlert('Error al cargar estadísticas actuales', 'error');
        }
    }

    function handleFileInput(event) {
        const file = event.target.files[0];
        if (!file) return;

        if (!file.type.includes('text') && !file.name.endsWith('.txt') && !file.name.endsWith('.csv')) {
            showAlert('Por favor, selecciona un archivo de texto (.txt o .csv)', 'error');
            return;
        }

        const reader = new FileReader();
        reader.onload = (e) => {
            const content = e.target.result;
            domainsTextarea.value = content;
            showAlert(`Archivo cargado: ${file.name} (${formatFileSize(file.size)})`, 'info');
        };
        
        reader.onerror = () => {
            showAlert('Error al leer el archivo', 'error');
        };

        reader.readAsText(file);
    }

    async function updateDatabase() {
        const domainsText = domainsTextarea.value.trim();
        
        if (!domainsText) {
            showAlert('Por favor, ingresa la lista de dominios', 'error');
            return;
        }

        // Validar formato básico
        const lines = domainsText.split('\n').filter(line => line.trim() && !line.startsWith('#'));
        const validDomains = lines.filter(line => {
            const domain = line.trim().toLowerCase();
            return domain.includes('.') && !domain.includes(' ');
        });

        if (validDomains.length === 0) {
            showAlert('No se encontraron dominios válidos en el texto', 'error');
            return;
        }

        if (validDomains.length < lines.length) {
            const invalid = lines.length - validDomains.length;
            showAlert(`Se ignoraron ${invalid} líneas con formato inválido`, 'info');
        }

        // Mostrar progreso
        updateBtn.disabled = true;
        progressContainer.style.display = 'block';
        progressFill.style.width = '30%';

        try {
            // Enviar a background script
            const response = await chrome.runtime.sendMessage({
                type: 'UPDATE_PHISHING_DB',
                domainsText: validDomains.join('\n')
            });

            progressFill.style.width = '100%';

            setTimeout(() => {
                progressContainer.style.display = 'none';
                updateBtn.disabled = false;
                progressFill.style.width = '0%';

                if (response.success) {
                    showAlert(response.message, 'success');
                    loadCurrentStats(); // Recargar estadísticas
                    
                    // Limpiar textarea después del éxito
                    domainsTextarea.value = '';
                } else {
                    showAlert(response.message, 'error');
                }
            }, 500);

        } catch (error) {
            progressContainer.style.display = 'none';
            updateBtn.disabled = false;
            progressFill.style.width = '0%';
            
            console.error('Error updating database:', error);
            showAlert('Error de comunicación con la extensión', 'error');
        }
    }

    function clearTextarea() {
        domainsTextarea.value = '';
        fileInput.value = '';
        showAlert('Área de texto limpiada', 'info');
    }

    function loadSampleData() {
        const sampleDomains = `# Ejemplo de lista de dominios maliciosos
# Las líneas que empiecen con # son comentarios y se ignorarán

00000000000000000000000000000000000000000.xyz
00000000000000000000000000000000000000dfjjjhv.000webhostapp.com
000000000000000000000000000000000000dbscrfg.000webhostapp.com
000000000000000000000000000.vstarbet555.com
000000000000000000000000000yteyeuya.000webhostapp.com
0000000000000000000000000.findyourjacket.com
00000000000000000000000056000005-102299.weeblysite.com
00000000000000000000000.fielty.mx
000000000000000000.cybertek-peru.com
000000000000000000gg.000webhostapp.com
00000000000000000dhl.000webhostapp.com
00000000000000000update.emy.ba
000000000000000ooooo.000webhostapp.com
000-00-000-000000.pages.dev
0000000000000f0i0c0o0h0s0a.000webhostapp.com
0000000000c0.x9xcax2a.workers.dev
000000000a0uutlook.weebly.com
00000000883838383992929292222.ratingandreviews.in
00000000920.us-south.cf.appdomain.cloud
0000000095.godaddysites.com
000000009980011200.ml
00000002.c1.biz
0000000666666.000webhostapp.com
0000000o.weebly.com
0000000wer.000webhostapp.com
000000541840000.co.vu
fake-paypal-login.com
amazon-security-update.net
microsoft-account-verify.org
google-security-check.info
apple-id-suspended.tk
bank-security-notice.ml
urgent-account-verification.ga
secure-login-portal.cf
phishing-example.com
malicious-site.net`;

        domainsTextarea.value = sampleDomains;
        showAlert('Datos de ejemplo cargados. ¡Ahora puedes probar la actualización!', 'info');
    }

    function showAlert(message, type) {
        // Limpiar alertas anteriores
        alertContainer.innerHTML = '';

        const alert = document.createElement('div');
        alert.className = `alert alert-${type}`;
        alert.style.display = 'flex';

        const icon = getAlertIcon(type);
        alert.innerHTML = `
            <span class="material-icons">${icon}</span>
            <span>${message}</span>
        `;

        alertContainer.appendChild(alert);

        // Auto-ocultar después de 5 segundos (excepto errores)
        if (type !== 'error') {
            setTimeout(() => {
                if (alert.parentNode) {
                    alert.style.opacity = '0';
                    alert.style.transform = 'translateY(-10px)';
                    setTimeout(() => {
                        if (alert.parentNode) {
                            alert.parentNode.removeChild(alert);
                        }
                    }, 300);
                }
            }, 5000);
        }
    }

    function getAlertIcon(type) {
        const icons = {
            success: 'check_circle',
            error: 'error',
            info: 'info',
            warning: 'warning'
        };
        return icons[type] || 'info';
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Agregar drag & drop functionality
    const dragEvents = ['dragenter', 'dragover', 'dragleave', 'drop'];
    
    dragEvents.forEach(eventName => {
        domainsTextarea.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    ['dragenter', 'dragover'].forEach(eventName => {
        domainsTextarea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        domainsTextarea.addEventListener(eventName, unhighlight, false);
    });

    domainsTextarea.addEventListener('drop', handleDrop, false);

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        domainsTextarea.style.borderColor = '#1976d2';
        domainsTextarea.style.backgroundColor = '#e3f2fd';
    }

    function unhighlight(e) {
        domainsTextarea.style.borderColor = '#e0e0e0';
        domainsTextarea.style.backgroundColor = '#fafafa';
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
            const file = files[0];
            
            if (file.type.includes('text') || file.name.endsWith('.txt') || file.name.endsWith('.csv')) {
                const reader = new FileReader();
                reader.onload = (event) => {
                    domainsTextarea.value = event.target.result;
                    showAlert(`Archivo arrastrado cargado: ${file.name}`, 'success');
                };
                reader.readAsText(file);
            } else {
                showAlert('Por favor, arrastra un archivo de texto (.txt o .csv)', 'error');
            }
        }
    }

    // Contador de dominios en tiempo real
    domainsTextarea.addEventListener('input', () => {
        const text = domainsTextarea.value.trim();
        if (text) {
            const lines = text.split('\n').filter(line => 
                line.trim() && 
                !line.startsWith('#') && 
                line.includes('.') && 
                !line.includes(' ')
            );
            
            const counter = document.getElementById('domain-counter');
            if (!counter) {
                const counterEl = document.createElement('div');
                counterEl.id = 'domain-counter';
                counterEl.style.cssText = `
                    position: absolute;
                    bottom: 8px;
                    right: 8px;
                    background: rgba(25, 118, 210, 0.1);
                    color: #1976d2;
                    padding: 4px 8px;
                    border-radius: 12px;
                    font-size: 11px;
                    font-weight: 500;
                `;
                domainsTextarea.parentNode.appendChild(counterEl);
            }
            
            document.getElementById('domain-counter').textContent = `${lines.length} dominios válidos`;
        } else {
            const counter = document.getElementById('domain-counter');
            if (counter) {
                counter.remove();
            }
        }
    });

    // Atajos de teclado
    document.addEventListener('keydown', (e) => {
        // Ctrl/Cmd + Enter para actualizar
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            updateDatabase();
        }
        
        // Ctrl/Cmd + L para limpiar
        if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
            e.preventDefault();
            clearTextarea();
        }
        
        // Ctrl/Cmd + Shift + S para cargar ejemplo
        if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'S') {
            e.preventDefault();
            loadSampleData();
        }
    });

    // Mostrar atajos de teclado
    const shortcutsInfo = document.createElement('div');
    shortcutsInfo.style.cssText = `
        position: fixed;
        bottom: 16px;
        right: 16px;
        background: rgba(33, 33, 33, 0.8);
        color: white;
        padding: 12px;
        border-radius: 8px;
        font-size: 11px;
        max-width: 200px;
        opacity: 0;
        transition: opacity 0.3s;
    `;
    shortcutsInfo.innerHTML = `
        <strong>Atajos de teclado:</strong><br>
        Ctrl+Enter: Actualizar DB<br>
        Ctrl+L: Limpiar texto<br>
        Ctrl+Shift+S: Cargar ejemplo
    `;
    document.body.appendChild(shortcutsInfo);

    // Mostrar atajos al pasar sobre el textarea
    domainsTextarea.addEventListener('focus', () => {
        shortcutsInfo.style.opacity = '1';
    });

    domainsTextarea.addEventListener('blur', () => {
        setTimeout(() => {
            shortcutsInfo.style.opacity = '0';
        }, 2000);
    });
});