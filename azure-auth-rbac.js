(function (global) {

  console.log("🔹 Azure Auth RBAC Module Loaded");

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
      const parsed = JSON.parse(jsonPayload);
      console.log("✅ JWT decoded successfully");
      return parsed;
    } catch (err) {
      console.error("❌ JWT decode failed:", err);
      return null;
    }
  }

  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    if (!userRoles || userRoles.length === 0) {
      console.log("⚠ No user roles found");
      return false;
    }

    for (const role of rolesDisabled) {
      if (userRoles.includes(role)) {
        console.log("⛔ Access denied due to disabled role:", role);
        return false;
      }
    }

    if (!rolesEnabled.length) {
      console.log("⚠ No enabled roles configured");
      return false;
    }

    const allowed = rolesEnabled.some(role => userRoles.includes(role));

    console.log("🔐 Access check:", allowed);
    return allowed;
  }

  async function authenticate({
    redirectUrl,
    pageAccessConfigVar = {},
    componentAccessConfigVar = {}
  } = {}) {

    console.log("🔹 Azure Auth Module Running");

    let user = null;
    let userRoles = [];
    let currentHash = "";
    let isAccessTokenValid = false;
    let access_token = null;
    let id_token = null;

    let urlObj;
    try {
      urlObj = new URL(redirectUrl);
      currentHash = urlObj.hash || "";
      console.log("🌍 Current Path:", urlObj.pathname);
      console.log("🔎 Current Hash:", currentHash || "(empty)");
    } catch (err) {
      console.error("❌ Invalid redirect URL:", err.message);
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (urlObj.pathname.includes("/editor")) {
      console.log("🟣 Editor mode detected — bypassing auth logic");
      return {
        isAuthenticated: false,
        loginRedirectUrl: redirectUrl
      };
    }

    if (!currentHash) {

      if (urlObj.pathname.endsWith("/Login")) {
        console.log("🟡 Already on Login page — no redirect");
        return {
          isAuthenticated: false,
          loginRedirectUrl: null
        };
      }

      console.log("⚠ No hash found — redirecting to Login");

      urlObj.hash = "";

      const pathParts = urlObj.pathname.split("/").filter(Boolean);

      if (pathParts.length > 0) {
        pathParts[pathParts.length - 1] = "Login";
      } else {
        pathParts.push("Login");
      }

      urlObj.pathname = "/" + pathParts.join("/");

      console.log("➡ Redirect URL:", urlObj.toString());

      return {
        isAuthenticated: false,
        loginRedirectUrl: urlObj.toString()
      };
    }

    console.log("✅ Hash detected — processing tokens");

    const params = new URLSearchParams(currentHash.substring(1));

    access_token = params.get("access_token");
    id_token = params.get("id_token");

    if (access_token) {
      console.log("✅ Access token found");
      isAccessTokenValid = true;
    } else {
      console.log("❌ No access token found");
    }

    if (id_token) {
      console.log("🔓 ID token found — decoding");
      user = decodeJwt(id_token);

      if (user) {
        userRoles = Array.isArray(user.roles) ? user.roles : [];
        console.log("👤 User:", user?.email || user?.upn || user?.name || "Unknown");
        console.log("🎭 Roles:", userRoles);
      }
    }

    const pageAccessConfig =
      typeof pageAccessConfigVar === "string"
        ? JSON.parse(pageAccessConfigVar)
        : pageAccessConfigVar;

    const componentAccessConfig =
      typeof componentAccessConfigVar === "string"
        ? JSON.parse(componentAccessConfigVar)
        : componentAccessConfigVar;

    const pages = {};
    console.log("📄 Computing page access...");
    for (const pageId in pageAccessConfig) {
      const config = pageAccessConfig[pageId];
      pages[pageId] = {
        hasAccess: hasAccess(
          userRoles,
          config?.roles_enabled || [],
          config?.roles_disabled || []
        )
      };
      console.log("Page:", pageId, "Access:", pages[pageId].hasAccess);
    }

    const components = {};
    console.log("🧩 Computing component access...");
    for (const compId in componentAccessConfig) {
      const config = componentAccessConfig[compId];
      components[compId] = {
        hasAccess: hasAccess(
          userRoles,
          config?.roles_enabled || [],
          config?.roles_disabled || []
        )
      };
      console.log("Component:", compId, "Access:", components[compId].hasAccess);
    }

    console.log("🎯 Authentication complete:", isAccessTokenValid);

    return {
      isAuthenticated: isAccessTokenValid,
      access_token,
      id_token,
      user,
      roles: userRoles,
      pages,
      components
    };
  }

  global.RetoolAuthFramework = {
    authenticate,
    hasAccess
  };

})(window);
