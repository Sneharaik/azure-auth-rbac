(function (global) {

  function parseConfig(config) {
    if (!config) {
      console.warn("parseConfig: No config provided");
      return {};
    }

    if (typeof config === "string") {
      try {
        const parsed = JSON.parse(config);
        console.log("parseConfig: Parsed JSON config", parsed);
        return parsed;
      } catch (e) {
        console.error("parseConfig: Invalid JSON config", e);
        return {};
      }
    }

    console.log("parseConfig: Using object config", config);
    return config;
  }

  function decodeJwt(token) {
    try {
      const base64 = token.split(".")[1]
        .replace(/-/g, "+")
        .replace(/_/g, "/");

      const decoded = JSON.parse(
        decodeURIComponent(
          atob(base64)
            .split("")
            .map(c => "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2))
            .join("")
        )
      );

      console.log("decodeJwt: Decoded token", decoded);
      return decoded;

    } catch (e) {
      console.error("decodeJwt: Failed to decode token", e);
      return null;
    }
  }

  function hasAccess(userRoles = [], rolesEnabled = [], rolesDisabled = []) {
    console.log("hasAccess: Checking access", {
      userRoles,
      rolesEnabled,
      rolesDisabled
    });

    if (!userRoles.length) {
      console.warn("hasAccess: No user roles found");
      return false;
    }

    if (rolesDisabled.some(r => userRoles.includes(r))) {
      console.warn("hasAccess: Role is explicitly disabled");
      return false;
    }

    if (!rolesEnabled.length) {
      console.warn("hasAccess: No enabled roles defined");
      return false;
    }

    const allowed = rolesEnabled.some(r => userRoles.includes(r));
    console.log("hasAccess: Final decision", allowed);

    return allowed;
  }

  function buildACL(config, userRoles, isAuthenticated) {
    console.log("buildACL: Starting ACL generation", {
      config,
      userRoles,
      isAuthenticated
    });

    const result = {};
    const keys = Object.keys(config || {});

    if (!keys.length) {
      console.warn("buildACL: No config keys found");
      return result;
    }

    for (const key of keys) {
      console.log("buildACL: Processing key", key);

      if (isAuthenticated && (!userRoles || !userRoles.length)) {
        console.warn("buildACL: No roles but authenticated — granting access", key);
        result[key] = { hasAccess: true };
        continue;
      }

      const { roles_enabled = [], roles_disabled = [] } = config[key] || {};

      if (!roles_enabled.length && !roles_disabled.length) {
        console.warn("buildACL: No role restrictions — granting access", key);
        result[key] = { hasAccess: true };
        continue;
      }

      result[key] = {
        hasAccess: hasAccess(userRoles, roles_enabled, roles_disabled)
      };

      console.log("buildACL: Result for key", key, result[key]);
    }

    console.log("buildACL: Final ACL result", result);
    return result;
  }

  async function authenticate({
    redirectUrl,
    pageAccessConfigVar = {},
    componentAccessConfigVar = {}
  } = {}) {

    console.log("authenticate: Starting authentication flow");

    let url;
    try {
      url = new URL(redirectUrl);
      console.log("authenticate: Parsed redirect URL", url.toString());
    } catch (e) {
      console.error("authenticate: Invalid redirect URL", e);
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (url.pathname.includes("/editor")) {
      console.warn("authenticate: Editor detected — skipping auth");
      return { isAuthenticated: false, loginRedirectUrl: null };
    }

    if (!url.hash) {
      console.warn("authenticate: No hash found in URL");

      if (url.pathname.endsWith("/Login")) {
        console.warn("authenticate: Already on Login page");
        return { isAuthenticated: false, loginRedirectUrl: null };
      }

      const parts = url.pathname.split("/").filter(Boolean);
      parts[parts.length - 1] = "Login";
      url.pathname = "/" + parts.join("/");
      url.hash = "";

      console.log("authenticate: Redirecting to login", url.toString());

      return {
        isAuthenticated: false,
        loginRedirectUrl: url.toString()
      };
    }

    const params = new URLSearchParams(url.hash.substring(1));
    const access_token = params.get("access_token");
    const id_token = params.get("id_token");

    console.log("authenticate: Tokens extracted", {
      hasAccessToken: !!access_token,
      hasIdToken: !!id_token
    });

    const isAuthenticated = !!access_token;

    const user = id_token ? decodeJwt(id_token) : null;
    const roles = Array.isArray(user?.roles) ? user.roles : [];
    

    console.log("authenticate: User roles detected", roles);

    const pageConfig = parseConfig(pageAccessConfigVar);
    const componentConfig = parseConfig(componentAccessConfigVar);

    const pages = buildACL(pageConfig, roles, isAuthenticated);
    const components = buildACL(componentConfig, roles, isAuthenticated);

    const generatedACL = { ...pages, ...components };

    console.log("authenticate: Final generated ACL", generatedACL);

    return {
      isAuthenticated,
      access_token,
      id_token,
      user,
      roles,
      pages,
      components,
      generatedACL,
      redirectUrl
    };
  }

  global.RetoolAuthFramework = {
    authenticate,
    hasAccess
  };

})(window);
