// azure-auth-rbac.js
(function (global) {
  console.log("🔹 Azure Auth RBAC Module Loaded");

  // --- Utility: decode JWT ---
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

  // --- Utility: check role access ---
  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    if (!userRoles || userRoles.length === 0) return false;
    for (const role of rolesDisabled) if (userRoles.includes(role)) return false;
    if (!rolesEnabled.length) return false;
    return rolesEnabled.some(role => userRoles.includes(role));
  }

  // --- Main authentication function ---
  async function authenticate({
    redirectUrl,               // URL with Azure hash after login
    pageAccessConfigVar = {},  // page access config
    componentAccessConfigVar = {}, // component access config
    storageKeyPrefix = "azure" // key prefix for localStorage
  } = {}) {
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

    // --- Process tokens from hash ---
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
    } else {
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

    // --- Parse access configs ---
    console.log("⚙️ Parsing access configurations...");
    let pageAccessConfig = typeof pageAccessConfigVar === "string" ? JSON.parse(pageAccessConfigVar) : pageAccessConfigVar;
    let componentAccessConfig = typeof componentAccessConfigVar === "string" ? JSON.parse(componentAccessConfigVar) : componentAccessConfigVar;

    // --- Compute page access ---
    console.log("⚙️ Computing page access...");
    const pages = {};
    for (const pageId in pageAccessConfig) {
      const config = pageAccessConfig[pageId];
      pages[pageId] = {
        hasAccess: hasAccess(userRoles, config?.roles_enabled || [], config?.roles_disabled || [])
      };
    }
    console.log("✓ Page access computed:", pages);

    // --- Compute component access ---
    console.log("⚙️ Computing component access...");
    const components = {};
    for (const compId in componentAccessConfig) {
      const config = componentAccessConfig[compId];
      components[compId] = {
        hasAccess: hasAccess(userRoles, config?.roles_enabled || [], config?.roles_disabled || [])
      };
    }
    console.log("✓ Component access computed:", components);

    // --- Prepare final result ---
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

  // --- Expose globally ---
  global.RetoolAuthFramework = {
    authenticate,
    hasAccess
  };

})(window);
