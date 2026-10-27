const express = require('express');
const session = require('express-session');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');
const msal = require('@azure/msal-node');
require('dotenv').config();

const app = express();

// ==========================================
// 1. SEGURIDAD Y CONFIGURACIÓN DE REVERSE PROXY
// ==========================================

app.disable('x-powered-by');

const trustProxyVal = process.env.TRUST_PROXY || 1;
app.set('trust proxy', isNaN(trustProxyVal) ? trustProxyVal : Number(trustProxyVal));

app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
                scriptSrcAttr: ["'unsafe-inline'"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:", "https://images.unsplash.com"],
                connectSrc: ["'self'"],
                objectSrc: ["'none'"],
                upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null
            }
        },
        crossOriginEmbedderPolicy: false,
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        frameguard: { action: 'sameorigin' }
    })
);

const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 500,
    standardHeaders: true,
    legacyHeaders: false
});
app.use(generalLimiter);

app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

// ==========================================
// 2. SESIONES SEGURAS
// ==========================================

const isProduction = process.env.NODE_ENV === 'production';
const sessionSecret = process.env.SESSION_SECRET || (!isProduction ? crypto.randomBytes(32).toString('hex') : '');
if (!sessionSecret) {
    throw new Error('SESSION_SECRET must be configured in production.');
}

app.use(session({
    name: 'vtf_session_id',
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 8 * 60 * 60 * 1000 // 8 horas
    }
}));

// ==========================================
// 3. MICROSOFT ENTRA ID (MSAL + MICROSOFT GRAPH)
// ==========================================

const ENTRA_ENABLED       = process.env.ENTRA_ID_ENABLED === 'true';
const ENTRA_TENANT_ID     = process.env.ENTRA_ID_TENANT_ID || '';
const ENTRA_CLIENT_ID     = process.env.ENTRA_ID_CLIENT_ID || '';
const ENTRA_CLIENT_SECRET = process.env.ENTRA_ID_CLIENT_SECRET || '';
const ENTRA_REDIRECT_URI  = process.env.ENTRA_ID_REDIRECT_URI || 'http://localhost:3000/auth/callback';

// Nombres de los grupos de seguridad creados en Entra ID
const ENTRA_TI_GROUP    = process.env.ENTRA_ID_TI_GROUP_NAME || 'Equipo TI';
const ENTRA_ADMIN_GROUP = process.env.ENTRA_ID_ADMIN_GROUP_NAME || 'Admins-Intranet';

// Configuración MSAL para flujo Authorization Code (OIDC)
const msalConfig = {
    auth: {
        clientId: ENTRA_CLIENT_ID,
        authority: `https://login.microsoftonline.com/${ENTRA_TENANT_ID}`,
        clientSecret: ENTRA_CLIENT_SECRET
    },
    system: {
        loggerOptions: {
            loggerCallback(loglevel, message) {
                if (process.env.NODE_ENV !== 'production') {
                    console.log('[MSAL]', message);
                }
            },
            piiLoggingEnabled: false,
            logLevel: msal.LogLevel.Warning
        }
    }
};

// Scopes necesarios:
// - openid / profile / email: datos básicos del usuario
// - GroupMember.Read.All: leer grupos del usuario via Microsoft Graph
const ENTRA_SCOPES = [
    'openid',
    'profile',
    'email',
    'https://graph.microsoft.com/GroupMember.Read.All'
];

let msalClient = null;
if (ENTRA_ENABLED && ENTRA_TENANT_ID && ENTRA_CLIENT_ID && ENTRA_CLIENT_SECRET) {
    msalClient = new msal.ConfidentialClientApplication(msalConfig);
    console.log('✅ Microsoft Entra ID (MSAL) inicializado correctamente.');
} else {
    console.log('⚠️  Microsoft Entra ID en modo SIMULACIÓN (ENTRA_ID_ENABLED=false o credenciales vacías).');
}

/**
 * Consulta a Microsoft Graph API los nombres de los grupos de seguridad del usuario.
 * Requiere que la app tenga el permiso GroupMember.Read.All habilitado en Entra ID.
 * @param {string} accessToken - Token de acceso obtenido de MSAL
 * @returns {Promise<string[]>} - Lista de nombres de grupo
 */
async function getUserGroupsFromGraph(accessToken) {
    try {
        const response = await fetch('https://graph.microsoft.com/v1.0/me/memberOf?$select=displayName,id', {
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errText = await response.text();
            console.error('[GRAPH] Error al obtener grupos:', response.status, errText);
            return [];
        }

        const data = await response.json();
        // Extraer solo grupos de seguridad (#microsoft.graph.group)
        const groupNames = (data.value || [])
            .filter(g => g['@odata.type'] === '#microsoft.graph.group' || g.displayName)
            .map(g => g.displayName)
            .filter(Boolean);

        return groupNames;
    } catch (err) {
        console.error('[GRAPH] Error de conexión con Microsoft Graph:', err.message);
        return [];
    }
}

/**
 * Evalúa los grupos de Entra ID del usuario y retorna su rol en la intranet.
 * @param {string[]} groups - Lista de nombres de grupo del usuario
 * @returns {{ role, roleLabel, isTI, isAdmin }}
 */
function resolveRoleFromGroups(groups) {
    const isAdmin = groups.includes(ENTRA_ADMIN_GROUP);
    const isTI    = isAdmin || groups.includes(ENTRA_TI_GROUP);

    if (isAdmin) {
        return { role: 'admin', roleLabel: 'Administrador de Intranet', isTI: true, isAdmin: true };
    }
    if (isTI) {
        return { role: 'ti', roleLabel: 'Especialista TI', isTI: true, isAdmin: false };
    }
    return { role: 'colaborador', roleLabel: 'Público General', isTI: false, isAdmin: false };
}

// ==========================================
// 4. CATÁLOGO DE SERVICIOS (JSON persistente)
// ==========================================

const SERVICES_FILE_PATH = path.join(__dirname, 'data', 'services.json');

function loadServices() {
    try {
        if (!fs.existsSync(SERVICES_FILE_PATH)) return [];
        return JSON.parse(fs.readFileSync(SERVICES_FILE_PATH, 'utf8'));
    } catch (err) {
        console.error('Error al leer services.json:', err);
        return [];
    }
}

function saveServices(list) {
    try {
        fs.mkdirSync(path.dirname(SERVICES_FILE_PATH), { recursive: true });
        fs.writeFileSync(SERVICES_FILE_PATH, JSON.stringify(list, null, 2), 'utf8');
        return true;
    } catch (err) {
        console.error('Error al guardar services.json:', err);
        return false;
    }
}

const BASE_AREAS = [
    { id: 'administracion', nombre: 'Administración',                     icono: '📊', descripcion: 'Finanzas corporativas, compras, RRHH y contabilidad' },
    { id: 'logistica',      nombre: 'Logística',                          icono: '📦', descripcion: 'Operaciones de almacén, existencias y seguimiento de despachos' },
    { id: 'ti',             nombre: 'Tecnologías de la Información (TI)', icono: '💻', descripcion: 'Herramientas técnicas, Jira, accesos y servidores de infraestructura' }
];

function normalizeInternalAddress(value) {
    const address = String(value || '').trim();
    if (!address) return null;

    try {
        const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(address) ? address : `http://${address}`);
        if (!['http:', 'https:'].includes(url.protocol)
            || url.username || url.password
            || url.pathname !== '/' || url.search || url.hash) {
            return null;
        }
        return { address: url.host, targetUrl: url.origin };
    } catch {
        return null;
    }
}

function normalizeExternalUrl(value) {
    try {
        const url = new URL(String(value || '').trim());
        if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
        return url.href;
    } catch {
        return null;
    }
}

// ==========================================
// 5. DATOS GENERALES Y MIDDLEWARES AUTH
// ==========================================

const COMPANY_DOMAIN = process.env.COMPANY_DOMAIN || '@example.com';
const COMPANY_NAME   = (process.env.COMPANY_NAME || 'VITAFOODS').replace(/\s+SPA$/i, '').trim();

app.use((req, res, next) => {
    res.locals.companyName = COMPANY_NAME;
    next();
});

const requireAuth = (req, res, next) => {
    if (!req.session?.user) return res.redirect('/');
    next();
};

const requireAdmin = (req, res, next) => {
    if (!req.session?.user?.isAdmin) {
        return res.status(403).json({
            error: 'Permiso denegado: Se requiere membresía en el grupo Admins-Intranet de Entra ID.'
        });
    }
    next();
};

// ==========================================
// 6. RUTAS DE AUTENTICACIÓN
// ==========================================

// ── Pantalla de inicio ──────────────────────────────────────────────────────
app.get('/', (req, res) => {
    if (req.session?.user) return res.redirect('/dashboard');

    const errorMsg = req.query.error ? decodeURIComponent(req.query.error) : null;
    res.render('login', {
        error: errorMsg,
        companyName: COMPANY_NAME,
        companyDomain: COMPANY_DOMAIN,
        entraEnabled: ENTRA_ENABLED
    });
});

// ── Iniciar flujo OAuth2 de Entra ID ────────────────────────────────────────
// Cuando ENTRA_ID_ENABLED=true, este endpoint redirige al portal de Microsoft
app.get('/auth/login', async (req, res) => {
    if (!msalClient) {
        return res.redirect('/?error=' + encodeURIComponent('Entra ID no está configurado. Contacta al administrador TI.'));
    }

    try {
        const authCodeUrlParams = {
            scopes: ENTRA_SCOPES,
            redirectUri: ENTRA_REDIRECT_URI,
            state: req.session.id // anti-CSRF
        };

        // Si el usuario ya ingresó su email, pre-rellenar el campo en Microsoft
        if (req.session.loginHint) {
            authCodeUrlParams.loginHint = req.session.loginHint;
        }

        const authUrl = await msalClient.getAuthCodeUrl(authCodeUrlParams);
        req.session.authState = req.session.id;
        res.redirect(authUrl);
    } catch (err) {
        console.error('[ENTRA] Error generando URL de autenticación:', err);
        res.redirect('/?error=' + encodeURIComponent('Error al iniciar sesión con Microsoft. Intenta nuevamente.'));
    }
});

// ── Modo producción: recibe el email y redirige a Microsoft ──────────────────
app.post('/login', (req, res) => {
    if (!ENTRA_ENABLED) return res.redirect('/');

    const expectsJson = req.get('X-Requested-With') === 'XMLHttpRequest'
        && req.accepts('json');
    const identity = String(req.body.email || '').trim().toLowerCase();
    const email = identity.includes('@') ? identity : `${identity}${COMPANY_DOMAIN}`;
    if (!/^[^\s@]+@[^\s@]+$/.test(email) || !email.endsWith(COMPANY_DOMAIN.toLowerCase())) {
        const error = `Ingresa un usuario válido o un correo corporativo ${COMPANY_DOMAIN}`;
        if (expectsJson) return res.status(400).json({ error });

        return res.render('login', {
            error,
            companyName: COMPANY_NAME,
            companyDomain: COMPANY_DOMAIN,
            entraEnabled: ENTRA_ENABLED
        });
    }

    req.session.loginHint = email;
    if (expectsJson) {
        return req.session.save((err) => {
            if (err) {
                console.error('[LOGIN] Error al guardar la sesión:', err);
                return res.status(500).json({ error: 'No fue posible iniciar el inicio de sesión. Intenta nuevamente.' });
            }
            res.json({ redirectUrl: '/auth/login' });
        });
    }

    res.redirect('/auth/login');
});

// ── Callback de Entra ID (Microsoft nos devuelve aquí el código) ─────────────
app.get('/auth/callback', async (req, res) => {
    const { code, state, error, error_description } = req.query;

    // El usuario canceló o hubo error en Microsoft
    if (error) {
        console.error('[ENTRA] Error en callback:', error, error_description);
        return res.redirect(`/?error=${encodeURIComponent(error_description || error)}`);
    }

    // Validar anti-CSRF state
    if (!code || state !== req.session.authState) {
        return res.redirect('/?error=invalid_state');
    }

    if (!msalClient) {
        return res.redirect('/?error=entra_not_configured');
    }

    try {
        // Intercambiar el código por tokens de acceso e identidad
        const tokenResponse = await msalClient.acquireTokenByCode({
            code: String(code),
            scopes: ENTRA_SCOPES,
            redirectUri: ENTRA_REDIRECT_URI
        });

        const { account, accessToken, idTokenClaims } = tokenResponse;

        // Consultar los grupos del usuario en Microsoft Graph
        const userGroups = await getUserGroupsFromGraph(accessToken);
        const roleInfo   = resolveRoleFromGroups(userGroups);

        // Formatear el nombre del usuario (desde claims de Entra ID)
        const displayName = account.name
            || idTokenClaims?.name
            || idTokenClaims?.preferred_username
            || account.username;

        const userData = {
            email:     account.username.toLowerCase(),
            name:      displayName || account.username.split('@')[0],
            groups:    userGroups,
            ...roleInfo
        };

        // Regenerar ID de sesión para prevenir Session Fixation
        req.session.regenerate((err) => {
            if (err) return res.redirect('/?error=session_error');
            req.session.user = userData;
            req.session.save(() => res.redirect('/dashboard'));
        });

    } catch (err) {
        console.error('[ENTRA] Error al procesar el token de Entra ID:', err);
        res.redirect('/?error=token_failed');
    }
});

// ── Login de simulación (ENTRA_ID_ENABLED=false) ────────────────────────────
// Recibe solo el email. El sistema detecta automáticamente el grupo/rol
// usando los mismos criterios que usaría Entra ID en producción.
app.post('/login/demo', (req, res) => {
    if (ENTRA_ENABLED) return res.redirect('/auth/login');

    const email = String(req.body.email || '').trim().toLowerCase();

    if (!email) {
        return res.render('login', {
            error: 'Por favor ingresa tu correo corporativo.',
            companyName: COMPANY_NAME,
            companyDomain: COMPANY_DOMAIN,
            entraEnabled: ENTRA_ENABLED
        });
    }

    if (!email.endsWith(COMPANY_DOMAIN.toLowerCase())) {
        return res.render('login', {
            error: `Acceso restringido a cuentas corporativas ${COMPANY_DOMAIN}`,
            companyName: COMPANY_NAME,
            companyDomain: COMPANY_DOMAIN,
            entraEnabled: ENTRA_ENABLED
        });
    }

    // ── Detección automática de grupos (replica exactamente la lógica de Graph API) ──
    // En producción, estos grupos vienen de Microsoft Graph /me/memberOf.
    // Los emails registrados aquí deben coincidir con los miembros de los grupos en Entra ID.
    const ADMIN_EMAILS = (process.env.DEMO_ADMIN_EMAILS || `admin${COMPANY_DOMAIN}`)
        .split(',').map(e => e.trim().toLowerCase());

    const TI_EMAILS = (process.env.DEMO_TI_EMAILS || `soporte-ti${COMPANY_DOMAIN}`)
        .split(',').map(e => e.trim().toLowerCase());

    // Construir grupos del usuario (replica el claim de Entra ID)
    let groups = ['VTF-Colaboradores-General'];
    if (ADMIN_EMAILS.includes(email) || TI_EMAILS.includes(email)) {
        groups.push(ENTRA_TI_GROUP);
    }
    if (ADMIN_EMAILS.includes(email)) {
        groups.push(ENTRA_ADMIN_GROUP);
    }

    // Resolver rol a partir de los grupos (idéntico a resolveRoleFromGroups())
    const roleInfo = resolveRoleFromGroups(groups);

    // Formatear nombre desde el email
    const namePart = email.split('@')[0].replace(/[._-]/g, ' ');
    const displayName = namePart.replace(/\b\w/g, l => l.toUpperCase());

    const userData = { email, name: displayName, groups, ...roleInfo };

    req.session.regenerate((err) => {
        if (err) return res.redirect('/');
        req.session.user = userData;
        req.session.save(() => res.redirect('/dashboard'));
    });
});

// ── Cierre de sesión ─────────────────────────────────────────────────────────
app.get('/logout', (req, res) => {
    const userEmail = req.session?.user?.email || '';
    req.session.destroy(() => {
        res.clearCookie('vtf_session_id');

        // Si Entra ID estaba activo, cerrar también la sesión de Microsoft
        if (ENTRA_ENABLED && ENTRA_TENANT_ID) {
            const msLogoutUrl = `https://login.microsoftonline.com/${ENTRA_TENANT_ID}/oauth2/v2.0/logout`
                + `?post_logout_redirect_uri=${encodeURIComponent('http://localhost:' + PORT + '/')}`;
            return res.redirect(msLogoutUrl);
        }

        res.redirect('/');
    });
});

// ==========================================
// 7. DASHBOARD PRINCIPAL
// ==========================================

app.get('/dashboard', requireAuth, (req, res) => {
    const user        = req.session.user;
    const allServices = loadServices();

    const visibleServices = allServices.filter(s => {
        if (user.isAdmin) return true;
        if (user.isTI)    return s.requiredGroup === 'general' || s.requiredGroup === 'ti';
        return s.requiredGroup === 'general';
    });

    const areas = BASE_AREAS.map(area => {
        const areaServices  = visibleServices.filter(s => s.areaId === area.id);
        const isLocked      = area.id === 'ti' && !user.isTI && !user.isAdmin;
        return { ...area, servicios: areaServices, totalServicios: areaServices.length, isLocked };
    });

    res.render('dashboard', { user, companyName: COMPANY_NAME, areas, servicios: visibleServices });
});

// ==========================================
// 8. API DE ADMINISTRACIÓN DE SERVICIOS
// ==========================================

app.post('/api/services', requireAuth, requireAdmin, (req, res) => {
    const { nombre, areaId, icono, descripcion, accessType, internalIp, externalUrl, requiredGroup } = req.body;
    const cleanName = String(nombre || '').trim();
    if (!cleanName || !areaId || !descripcion) {
        return res.status(400).json({ error: 'Faltan campos obligatorios.' });
    }

    if (!BASE_AREAS.some(area => area.id === areaId)) {
        return res.status(400).json({ error: 'Selecciona un área válida.' });
    }

    const serviceType = accessType || 'internal';
    if (!['internal', 'direct', 'external'].includes(serviceType)) {
        return res.status(400).json({ error: 'Selecciona un tipo de servicio válido.' });
    }

    if (!['general', 'ti', 'admin'].includes(requiredGroup || 'general')) {
        return res.status(400).json({ error: 'Selecciona un permiso válido.' });
    }

    const normalizedAddress = serviceType !== 'external' ? normalizeInternalAddress(internalIp) : null;
    const normalizedExternalUrl = serviceType === 'external' ? normalizeExternalUrl(externalUrl) : null;
    if (serviceType !== 'external' && !normalizedAddress) {
        return res.status(400).json({
            error: serviceType === 'direct'
                ? 'Ingresa una URL interna válida con protocolo y puerto, por ejemplo https://192.0.2.10:11443.'
                : 'Ingresa una dirección interna válida, por ejemplo 192.0.2.10:8080.'
        });
    }
    if (serviceType === 'direct' && !/^https?:\/\//i.test(String(internalIp || '').trim())) {
        return res.status(400).json({ error: 'Para abrir una IP directamente, indica el protocolo y puerto, por ejemplo https://192.0.2.10:11443.' });
    }
    if (serviceType === 'external' && !normalizedExternalUrl) {
        return res.status(400).json({ error: 'Ingresa una URL externa válida que comience con http:// o https://.' });
    }

    const services = loadServices();
    const baseId = cleanName
        .toLowerCase().normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '').replace(/[^a-z0-9]/g, '-')
        .replace(/-+/g, '-').replace(/^-|-$/g, '') || `srv-${Date.now()}`;
    let cleanId = baseId;
    let suffix = 2;
    while (services.some(service => service.id.toLowerCase() === cleanId.toLowerCase())) {
        cleanId = `${baseId}-${suffix++}`;
    }

    const area = BASE_AREAS.find(a => a.id === areaId);
    const newService = {
        id: cleanId,
        nombre: cleanName,
        areaId,
        areaNombre: area ? area.nombre : areaId,
        icono: icono ? String(icono).trim() : '⚡',
        accessType: serviceType,
        url: serviceType === 'internal' ? `/proxy/${cleanId}` : `/launch/${cleanId}`,
        externalUrl: serviceType === 'external' ? normalizedExternalUrl : '',
        targetUrl: normalizedAddress?.targetUrl || '',
        internalIp: normalizedAddress?.address || '',
        descripcion: String(descripcion).trim(),
        requiredGroup: requiredGroup || 'general'
    };

    services.push(newService);
    if (!saveServices(services)) {
        return res.status(500).json({ error: 'No fue posible guardar el servicio en el catálogo.' });
    }
    res.status(201).json({ success: true, service: newService });
});

app.get('/api/services/:id', requireAuth, requireAdmin, (req, res) => {
    const service = loadServices().find(item => item.id === req.params.id);
    if (!service) return res.status(404).json({ error: 'Servicio no encontrado.' });
    res.json({ service });
});

app.put('/api/services/:id', requireAuth, requireAdmin, (req, res) => {
    const { nombre, areaId, icono, descripcion, accessType, internalIp, externalUrl, requiredGroup } = req.body;
    const services = loadServices();
    const i = services.findIndex(s => s.id === req.params.id);
    if (i === -1) return res.status(404).json({ error: 'Servicio no encontrado.' });

    const cleanName = String(nombre || '').trim();
    const cleanDescription = String(descripcion || '').trim();
    if (!cleanName || !cleanDescription) {
        return res.status(400).json({ error: 'El nombre y la descripción son obligatorios.' });
    }
    if (!BASE_AREAS.some(area => area.id === areaId)) {
        return res.status(400).json({ error: 'Selecciona un área válida.' });
    }
    if (!['internal', 'direct', 'external'].includes(accessType)) {
        return res.status(400).json({ error: 'Selecciona un tipo de servicio válido.' });
    }
    if (!['general', 'ti', 'admin'].includes(requiredGroup)) {
        return res.status(400).json({ error: 'Selecciona un permiso válido.' });
    }

    const normalizedAddress = accessType !== 'external' ? normalizeInternalAddress(internalIp) : null;
    const normalizedExternalUrl = accessType === 'external' ? normalizeExternalUrl(externalUrl) : null;
    if (accessType !== 'external' && !normalizedAddress) {
        return res.status(400).json({
            error: accessType === 'direct'
                ? 'Ingresa una URL interna válida con protocolo y puerto, por ejemplo https://192.0.2.10:11443.'
                : 'Ingresa una dirección interna válida, por ejemplo 192.0.2.10:8080.'
        });
    }
    if (accessType === 'direct' && !/^https?:\/\//i.test(String(internalIp || '').trim())) {
        return res.status(400).json({ error: 'Para abrir una IP directamente, indica el protocolo y puerto, por ejemplo https://192.0.2.10:11443.' });
    }
    if (accessType === 'external' && !normalizedExternalUrl) {
        return res.status(400).json({ error: 'Ingresa una URL externa válida que comience con http:// o https://.' });
    }

    const area = BASE_AREAS.find(a => a.id === areaId);
    services[i] = {
        ...services[i],
        nombre: cleanName,
        areaId,
        areaNombre: area.nombre,
        icono:         icono         ? String(icono).trim()         : services[i].icono,
        descripcion: cleanDescription,
        accessType,
        url: accessType === 'internal' ? `/proxy/${services[i].id}` : `/launch/${services[i].id}`,
        externalUrl: accessType === 'external' ? normalizedExternalUrl : '',
        internalIp: normalizedAddress?.address || '',
        targetUrl: normalizedAddress?.targetUrl || '',
        requiredGroup
    };

    if (!saveServices(services)) {
        return res.status(500).json({ error: 'No fue posible guardar los cambios en el catálogo.' });
    }
    res.json({ success: true, service: services[i] });
});

app.delete('/api/services/:id', requireAuth, requireAdmin, (req, res) => {
    let services = loadServices();
    const original = services.length;
    services = services.filter(s => s.id !== req.params.id);
    if (services.length === original) return res.status(404).json({ error: 'Servicio no encontrado.' });
    if (!saveServices(services)) {
        return res.status(500).json({ error: 'No fue posible actualizar el catálogo.' });
    }
    res.json({ success: true });
});

app.get('/launch/:service', requireAuth, (req, res) => {
    const key = String(req.params.service).toLowerCase();
    const service = loadServices().find(item => item.id.toLowerCase() === key);
    const user = req.session.user;

    if (!service || !['direct', 'external'].includes(service.accessType)) {
        return res.status(404).render('proxy-gateway', {
            status: 'not_found',
            user,
            service: service || { nombre: req.params.service, id: req.params.service },
            message: 'El servicio solicitado no existe o no está configurado para abrirse directamente.'
        });
    }

    if (service.requiredGroup === 'ti' && !user.isTI && !user.isAdmin) {
        return res.status(403).render('proxy-gateway', {
            status: 'forbidden', user, service,
            message: `Acceso denegado: Este recurso requiere el grupo '${ENTRA_TI_GROUP}' en Microsoft Entra ID.`
        });
    }

    if (service.requiredGroup === 'admin' && !user.isAdmin) {
        return res.status(403).render('proxy-gateway', {
            status: 'forbidden', user, service,
            message: `Acceso restringido: Solo para el grupo '${ENTRA_ADMIN_GROUP}'.`
        });
    }

    const destination = service.accessType === 'external'
        ? normalizeExternalUrl(service.externalUrl)
        : normalizeInternalAddress(service.targetUrl || service.internalIp)?.targetUrl;

    if (!destination) {
        console.error(`[LAUNCH] Destino inválido para el servicio ${service.id}.`);
        return res.status(500).render('proxy-gateway', {
            status: 'connection_error', user, service,
            message: 'El destino de este servicio no tiene una dirección válida. Contacta al administrador.'
        });
    }

    res.redirect(destination);
});

// ==========================================
// 9. REVERSE PROXY HACIA RECURSOS INTERNOS
// ==========================================

app.get('/proxy/:service', requireAuth, (req, res, next) => {
    const key      = String(req.params.service).toLowerCase();
    const services = loadServices();
    const service  = services.find(s => s.id.toLowerCase() === key);
    const user     = req.session.user;

    if (!service) {
        return res.status(404).render('proxy-gateway', {
            status: 'not_found', user,
            service: { nombre: req.params.service, id: req.params.service },
            message: 'El recurso solicitado no existe en el catálogo seguro de la intranet.'
        });
    }

    if (service.requiredGroup === 'ti' && !user.isTI && !user.isAdmin) {
        return res.status(403).render('proxy-gateway', {
            status: 'forbidden', user, service,
            message: `Acceso denegado: Este recurso requiere el grupo '${ENTRA_TI_GROUP}' en Microsoft Entra ID.`
        });
    }

    if (service.requiredGroup === 'admin' && !user.isAdmin) {
        return res.status(403).render('proxy-gateway', {
            status: 'forbidden', user, service,
            message: `Acceso restringido: Solo para el grupo '${ENTRA_ADMIN_GROUP}'.`
        });
    }

    if (service.accessType === 'direct' || service.accessType === 'external') {
        return res.status(400).render('proxy-gateway', {
            status: 'not_found', user, service,
            message: 'Este servicio se abre directamente desde su tarjeta y no utiliza el proxy de la intranet.'
        });
    }

    const target = service.targetUrl
        || process.env[`PROXY_TARGET_${service.id.toUpperCase()}`]
        || (service.internalIp ? `http://${service.internalIp}` : '');

    if (target) {
        return createProxyMiddleware({
            target,
            changeOrigin: true,
            secure: false,
            pathRewrite: { [`^/proxy/${key}`]: '' },
            on: {
                proxyReq(proxyReq, request) {
                    proxyReq.setHeader('X-Authenticated-User', request.session.user.email);
                    proxyReq.setHeader('X-User-Role',          request.session.user.role);
                    proxyReq.setHeader('X-Entra-Groups',       (request.session.user.groups || []).join(';'));
                    proxyReq.setHeader('X-Intranet-Gateway',   'VTF-Secure-Reverse-Proxy');
                    proxyReq.setHeader('X-Forwarded-Host',     request.get('host'));
                },
                error(err, request, response) {
                    console.error(`[PROXY ERROR] ${service.nombre}:`, err.message);
                    response.status(502).render('proxy-gateway', {
                        status: 'connection_error', user: request.session.user, service,
                        message: `No fue posible conectar con el servidor interno (${service.internalIp}).`
                    });
                }
            }
        })(req, res, next);
    }

    // Modo demo: muestra la pantalla del Gateway explicando la arquitectura
    res.render('proxy-gateway', {
        status: 'demo_active', user, service,
        message: 'Conexión Segura Establecida — Modo MVP. Configura PROXY_TARGET_* en .env para conectar al recurso real.'
    });
});

// ==========================================
// 10. MANEJADORES DE ERROR
// ==========================================

app.use((req, res) => {
    res.status(404).render('proxy-gateway', {
        status: 'not_found',
        user: req.session?.user || null,
        service: { nombre: 'Página no encontrada', id: '404' },
        message: 'La ruta solicitada no está disponible en la intranet.'
    });
});

app.use((err, req, res, next) => {
    console.error('[ERROR]', err.stack);
    res.status(500).send('<h1>Error interno</h1><p>El incidente ha sido registrado.</p>');
});

// ==========================================
// 11. INICIAR SERVIDOR
// ==========================================

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log('=======================================================');
    console.log(`🔒 Intranet VTF — Gateway Seguro & Entra ID`);
    console.log(`📍 URL:    http://localhost:${PORT}`);
    console.log(`☁️  Entra ID: ${ENTRA_ENABLED ? '🟢 ACTIVO' : '🟡 DEMO (ENTRA_ID_ENABLED=false)'}`);
    if (ENTRA_ENABLED) {
        console.log(`   Tenant: ${ENTRA_TENANT_ID}`);
        console.log(`   Grupo TI:    ${ENTRA_TI_GROUP}`);
        console.log(`   Grupo Admin: ${ENTRA_ADMIN_GROUP}`);
    }
    console.log(`🏢 Empresa: ${COMPANY_NAME}`);
    console.log('=======================================================');
});
