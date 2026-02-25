// azure-auth-rbac.js
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
      return JSON.parse(jsonPayload);
    } catch (err) {
      console.error("✗ JWT decode failed:", err);
      return null;
    }
  }

  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    if (!userRoles || userRoles.length === 0) return false;

    for (const role of rolesDisabled) {
      if (userRoles.includes(role)) return false;
    }

    if (!rolesEnabled.length) return false;

    return rolesEnabled.some(role => userRoles.includes(role));
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

    try {
      currentHash = new URL(redirectUrl).hash || "";
      console.log("Current URL Hash:", currentHash || "(empty)");
    } catch (err) {
      console.error("Could not parse redirect URL:", err.message);
    }

    // 🔴 If no hash → Redirect to Login page
    if (!currentHash) {
      console.log("⚠ No hash found in URL - Redirecting to Login page...");

      try {
        const urlObj = new URL(redirectUrl);

        // Remove hash
        urlObj.hash = "";

        const pathParts = urlObj.pathname.split("/").filter(Boolean);

        // Prevent redirect loop (if already on Login page)
        const lastSegment = pathParts[pathParts.length - 1];
        if (lastSegment !== "Login") {
          if (pathParts.length > 0) {
            pathParts[pathParts.length - 1] = "Login";
          } else {
            pathParts.push("Login");
          }

          urlObj.pathname = "/" + pathParts.join("/");

          console.log("➡ Redirecting to:", urlObj.toString());

          window.location.replace(urlObj.toString());
          return; // Stop execution after redirect
        } else {
          console.log("Already on Login page. No redirect needed.");
        }

      } catch (err) {
        console.error("Redirect failed:", err);
      }
    }

    // ✅ If hash exists → process tokens
    if (currentHash) {
      console.log("✓ Hash detected - Processing tokens...");
      const params = new URLSearchParams(currentHash.substring(1));

      access_token = params.get("access_token");
      id_token = params.get("id_token");

      if (access_token) {
        console.log("✓ Access token found");
        isAccessTokenValid = true;
      }

      if (id_token) {
        console.log("✓ ID token found - Decoding...");
        user = decodeJwt(id_token);

        if (user) {
          userRoles = Array.isArray(user.roles) ? user.roles : [];
          console.log(
            "✓ User decoded:",
            user?.email || user?.upn || user?.name || "Unknown"
          );
          console.log("✓ User roles:", userRoles);
        }
      }
    }

    console.log("⚙️ Parsing access configurations...");

    const pageAccessConfig =
      typeof pageAccessConfigVar === "string"
        ? JSON.parse(pageAccessConfigVar)
        : pageAccessConfigVar;

    const componentAccessConfig =
      typeof componentAccessConfigVar === "string"
        ? JSON.parse(componentAccessConfigVar)
        : componentAccessConfigVar;

    console.log("⚙️ Computing page access...");
    const pages = {};
    for (const pageId in pageAccessConfig) {
      const config = pageAccessConfig[pageId];
      pages[pageId] = {
        hasAccess: hasAccess(
          userRoles,
          config?.roles_enabled || [],
          config?.roles_disabled || []
        )
      };
    }
    console.log("✓ Page access computed:", pages);

    console.log("⚙️ Computing component access...");
    const components = {};
    for (const compId in componentAccessConfig) {
      const config = componentAccessConfig[compId];
      components[compId] = {
        hasAccess: hasAccess(
          userRoles,
          config?.roles_enabled || [],
          config?.roles_disabled || []
        )
      };
    }
    console.log("✓ Component access computed:", components);

    const result = {
      isAuthenticated: isAccessTokenValid,
      access_token,
      id_token,
      user,
      roles: userRoles,
      pages,
      components
    };

    console.log("✅ Azure Auth Module Complete");
    console.log("Final result:", result);

    return result;
  }

  global.RetoolAuthFramework = {
    authenticate,
    hasAccess
  };

})(window);
