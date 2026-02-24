// azure-auth-rbac.js
(function (global) {
  console.log("🔹 Azure Auth RBAC Module Loaded");

  // ============================================
  // CONFIGURATION (can be overridden)
  // ============================================
  const DEFAULT_CONFIG = {
    clientId: "8819e4d1-c889-4079-8562-6b2fa1495918",
    tenantId: "eb9970cc-4803-4f6a-9ad2-e9b46042c5fd",
    scopes: "openid profile email",
    storageKeyPrefix: "azure",
    loginPageId: "Login"
  };

  // ============================================
  // UTILITY FUNCTIONS
  // ============================================
  
  function decodeJwt(token) {
    try {
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace(/-/g, "+").replace(/_/g, "/");
      const jsonPayload = decodeURIComponent(
        atob(base64)
          .split("")
          .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
          .join("")
      );
      return JSON.parse(jsonPayload);
    } catch (err) {
      console.error("✗ JWT decode failed:", err);
      return null;
    }
  }

  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    if (!userRoles || userRoles.length === 0) return false;
    for (const role of rolesDisabled) if (userRoles.includes(role)) return false;
    if (!rolesEnabled.length) return false;
    return rolesEnabled.some(role => userRoles.includes(role));
  }

  // ============================================
  // NEW: INIT REDIRECT LOGIC
  // ============================================
  
  /**
   * Check authentication and redirect if needed
   * Call this on EVERY page load
   */
  function initRedirect(config = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    const isEditor = (typeof retoolContext !== 'undefined' && retoolContext.inEditorMode) || 
                     window.location.href.includes('/editor/');
    const currentPage = typeof retoolContext !== 'undefined' ? retoolContext.currentPage : null;
    
    console.log("🔹 Init Redirect Check:", { isEditor, currentPage });

    // Skip redirect in editor mode
    if (isEditor) {
      console.log("⚠️ Editor mode - skipping redirect");
      return { action: 'none', reason: 'editor_mode' };
    }

    // Check for token in localStorage
    const token = localStorage.getItem(`${cfg.storageKeyPrefix}_access_token`);
    const hasToken = !!token;

    console.log("Token present:", hasToken);

    // If no token and not on login page, redirect to login
    if (!hasToken && currentPage !== cfg.loginPageId) {
      console.log("❌ No token - Redirecting to Login");
      if (typeof utils !== 'undefined') {
        utils.openPage(cfg.loginPageId, {});
      }
      return { action: 'redirect_to_login', reason: 'no_token' };
    }

    // If has token but on login page, might be Azure redirect - stay on login to process
    if (hasToken && currentPage === cfg.loginPageId) {
      console.log("✅ Token exists - staying on Login to process Azure redirect");
      return { action: 'none', reason: 'processing_auth' };
    }

    console.log("✅ Auth check passed");
    return { action: 'none', reason: 'authenticated' };
  }

  // ============================================
  // NEW: START AZURE LOGIN
  // ============================================
  
  /**
   * Initiate Azure OAuth login
   * Call this from Login page button
   */
  function startAzureLogin(config = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    
    console.log("🔹 Azure Login Triggered");
    console.log("Client ID:", cfg.clientId);
    console.log("Tenant ID:", cfg.tenantId);
    console.log("Scopes:", cfg.scopes);

    // Get redirect URI (current URL without hash)
    const redirectUri = config.redirectUri || 
                       (typeof retoolContext !== 'undefined' ? retoolContext.url.split("#")[0] : window.location.href.split("#")[0]);

    console.log("Redirect URI:", redirectUri);

    // Build Azure OAuth URL
    const authUrl =
      `https://login.microsoftonline.com/${cfg.tenantId}/oauth2/v2.0/authorize` +
      `?client_id=${cfg.clientId}` +
      `&response_type=id_token%20token` +
      `&redirect_uri=${encodeURIComponent(redirectUri)}` +
      `&scope=${encodeURIComponent(cfg.scopes)}` +
      `&response_mode=fragment` +
      `&nonce=${Date.now()}`;

    console.log("🚀 Redirecting to Microsoft...");

    // Redirect to Azure
    if (typeof utils !== 'undefined') {
      utils.openUrl(authUrl, { newTab: false });
    } else {
      window.location.href = authUrl;
    }

    return {
      status: "redirecting_to_microsoft",
      redirectUri,
      authUrl
    };
  }

  // ============================================
  // MAIN AUTHENTICATE FUNCTION (Enhanced)
  // ============================================
  
  async function authenticate(options = {}) {
    const {
      redirectUrl = window.location.href,
      pageAccessConfigVar = {},
      componentAccessConfigVar = {},
      storageKeyPrefix = "azure",
      autoRedirectToHome = true,  // NEW: auto redirect to home after auth
      homePageId = "Home"          // NEW: home page ID
    } = options;

    console.log("🔹 Azure Auth Module Running");

    let user = null;
    let userRoles = [];
    let currentHash = "";
    let isAccessTokenValid = false;

    try {
      currentHash = new URL(redirectUrl).hash || "";
      console.log("Current URL Hash:", currentHash || "(empty)");
    } catch (err) {
      console.error("Could not parse redirect URL:", err.message);
    }

    // Process tokens from hash (Azure redirect)
    if (currentHash) {
      console.log("✓ Hash detected - Processing tokens...");
      const params = new URLSearchParams(currentHash.substring(1));
      const access_token = params.get("access_token");
      const id_token = params.get("id_token");

      if (access_token) {
        console.log("✓ Access token found - Storing...");
        localStorage.setItem(`${storageKeyPrefix}_access_token`, access_token);
        isAccessTokenValid = true;
      }

      if (id_token) {
        try {
          console.log("✓ ID token found - Decoding...");
          user = decodeJwt(id_token);
          if (user) {
            localStorage.setItem(`${storageKeyPrefix}_user_info`, JSON.stringify(user));
            userRoles = Array.isArray(user.roles) ? user.roles : [];
            console.log("✓ User decoded:", user?.email || user?.upn || user?.name || "Unknown");
            console.log("✓ User roles:", userRoles);
          }
        } catch (err) {
          console.error("✗ JWT decode error:", err.message);
        }
      }

      // NEW: Auto-redirect to home after processing tokens
      if (isAccessTokenValid && autoRedirectToHome && typeof utils !== 'undefined') {
        console.log("🔄 Auth successful - Redirecting to Home page");
        setTimeout(() => {
          utils.openPage(homePageId, {});
        }, 500); // Small delay to ensure storage is saved
      }
    } else {
      // Check localStorage for existing tokens
      console.log("⚠ No hash found - Checking localStorage...");
      const storedToken = localStorage.getItem(`${storageKeyPrefix}_access_token`);
      const storedUser = localStorage.getItem(`${storageKeyPrefix}_user_info`);
      if (storedToken && storedUser) {
        user = JSON.parse(storedUser);
        userRoles = Array.isArray(user?.roles) ? user.roles : [];
        isAccessTokenValid = true;
        console.log("✓ Loaded from storage:", user?.email || user?.name || "Unknown");
        console.log("✓ User roles:", userRoles);
      } else {
        console.log("⚠ No stored authentication found");
      }
    }

    // Parse access configs
    console.log("⚙️ Parsing access configurations...");
    let pageAccessConfig = typeof pageAccessConfigVar === "string" ? JSON.parse(pageAccessConfigVar) : pageAccessConfigVar;
    let componentAccessConfig = typeof componentAccessConfigVar === "string" ? JSON.parse(componentAccessConfigVar) : componentAccessConfigVar;

    // Compute page access
    console.log("⚙️ Computing page access...");
    const pages = {};
    for (const pageId in pageAccessConfig) {
      const config = pageAccessConfig[pageId];
      pages[pageId] = {
        hasAccess: hasAccess(userRoles, config?.roles_enabled || [], config?.roles_disabled || [])
      };
    }
    console.log("✓ Page access computed:", pages);

    // Compute component access
    console.log("⚙️ Computing component access...");
    const components = {};
    for (const compId in componentAccessConfig) {
      const config = componentAccessConfig[compId];
      components[compId] = {
        hasAccess: hasAccess(userRoles, config?.roles_enabled || [], config?.roles_disabled || [])
      };
    }
    console.log("✓ Component access computed:", components);

    // Prepare final result
    const result = {
      isAuthenticated: isAccessTokenValid,
      user,
      roles: userRoles,
      pages,
      components
    };

    console.log("✅ Azure Auth Module Complete");
    console.log("Final result:", result);

    return result;
  }

  // ============================================
  // NEW: LOGOUT FUNCTION
  // ============================================
  
  function logout(config = {}) {
    const cfg = { ...DEFAULT_CONFIG, ...config };
    console.log("🔹 Logging out...");
    
    // Clear localStorage
    localStorage.removeItem(`${cfg.storageKeyPrefix}_access_token`);
    localStorage.removeItem(`${cfg.storageKeyPrefix}_user_info`);
    
    console.log("✅ Logged out - Redirecting to Login");
    
    // Redirect to login
    if (typeof utils !== 'undefined') {
      utils.openPage(cfg.loginPageId, {});
    }
    
    return { status: 'logged_out' };
  }

  // ============================================
  // EXPOSE GLOBALLY
  // ============================================
  
  global.RetoolAuthFramework = {
    authenticate,
    hasAccess,
    initRedirect,       // NEW
    startAzureLogin,    // NEW
    logout              // NEW
  };

})(window);
