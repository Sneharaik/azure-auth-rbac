(function (global) {

  function parseConfig(config) {
    if (!config) return {};
    if (typeof config === "string") {
      try { return JSON.parse(config); }
      catch { return {}; }
    }
    return config;
  }

  function decodeJwt(token) {
    try {
      const base64 = token.split(".")[1]
        .replace(/-/g, "+")
        .replace(/_/g, "/");
      return JSON.parse(
        decodeURIComponent(
          atob(base64)
            .split("")
            .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
            .join("")
        )
      );
    } catch {
      return null;
    }
  }

  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    if (!userRoles.length) return false;
    if (rolesDisabled.some(r => userRoles.includes(r))) return false;
    if (!rolesEnabled.length) return false;
    return rolesEnabled.some(r => userRoles.includes(r));
  }

  function buildACL(config, userRoles, isAuthenticated) {
    const result = {};
    const keys = Object.keys(config || {});

    if (!keys.length) return result;

    for (const key of keys) {
      if (isAuthenticated && (!userRoles || !userRoles.length)) {
        result[key] = { hasAccess: true };
        continue;
      }

      const { roles_enabled = [], roles_disabled = [] } = config[key] || {};

      if (!roles_enabled.length && !roles_disabled.length) {
        result[key] = { hasAccess: true };
        continue;
      }

      result[key] = {
        hasAccess: hasAccess(userRoles, roles_enabled, roles_disabled)
      };
    }

    return result;
  }

  async function authenticate({
    redirectUrl,
    pageAccessConfigVar = {},
    componentAccessConfigVar = {}
  } = {}) {

    let url;
    try {
      url = new URL(redirectUrl);
    } catch {
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (url.pathname.includes("/editor")) {
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (!url.hash) {
      if (url.pathname.endsWith("/Login")) {
        return { isAuthenticated: false, loginRedirectUrl: null };
      }

      const parts = url.pathname.split("/").filter(Boolean);
      parts[parts.length - 1] = "Login";
      url.pathname = "/" + parts.join("/");
      url.hash = "";

      return {
        isAuthenticated: false,
        loginRedirectUrl: url.toString()
      };
    }

    const params = new URLSearchParams(url.hash.substring(1));
    const access_token = params.get("access_token");
    const id_token = params.get("id_token");

    const isAuthenticated = !!access_token;

    const user = id_token ? decodeJwt(id_token) : null;
    const roles = Array.isArray(user?.roles) ? user.roles : [];

    const pageConfig = parseConfig(pageAccessConfigVar);
    const componentConfig = parseConfig(componentAccessConfigVar);

    const pages = buildACL(pageConfig, roles, isAuthenticated);
    const components = buildACL(componentConfig, roles, isAuthenticated);

    const generatedACL = { ...pages, ...components };

    return {
      isAuthenticated,
      access_token,
      id_token,
      user,
      roles,
      pages,
      components,
      generatedACL
    };
  }

  global.RetoolAuthFramework = {
    authenticate,
    hasAccess
  };

})(window);
