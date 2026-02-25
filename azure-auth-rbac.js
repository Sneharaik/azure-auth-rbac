(function (global) {

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
    } catch (err) {
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (urlObj.pathname.includes("/editor")) {
      return {
        isAuthenticated: false,
        loginRedirectUrl: redirectUrl
      };
    }

    if (!currentHash) {

      if (urlObj.pathname.endsWith("/Login")) {
        return {
          isAuthenticated: false,
          loginRedirectUrl: null
        };
      }

      urlObj.hash = "";

      const pathParts = urlObj.pathname.split("/").filter(Boolean);

      if (pathParts.length > 0) {
        pathParts[pathParts.length - 1] = "Login";
      } else {
        pathParts.push("Login");
      }

      urlObj.pathname = "/" + pathParts.join("/");

      return {
        isAuthenticated: false,
        loginRedirectUrl: urlObj.toString()
      };
    }

    const params = new URLSearchParams(currentHash.substring(1));

    access_token = params.get("access_token");
    id_token = params.get("id_token");

    if (access_token) {
      isAccessTokenValid = true;
    }

    if (id_token) {
      user = decodeJwt(id_token);
      if (user) {
        userRoles = Array.isArray(user.roles) ? user.roles : [];
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
