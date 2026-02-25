// Filename: retool-azure-auth.js
// Retool compatible custom library for Azure-style auth & ACL

const RetoolAuthFramework = (() => {
  /**
   * Parse URL hash parameters into a dictionary
   * @param {string} url 
   * @returns {Object} key-value pairs from URL hash
   */
  function parseHashParams(url) {
    const hash = url.split('#')[1] || '';
    const params = {};
    hash.split('&').forEach(pair => {
      const [key, value] = pair.split('=');
      if (key && value) {
        params[key] = decodeURIComponent(value);
      }
    });
    return params;
  }

  /**
   * Generate ACL dictionary based on pageConfig, componentConfig, and roles
   * @param {Object} pageConfig 
   * @param {Object} componentConfig 
   * @param {Array} roles 
   * @returns {Object} ACL dictionary
   */
  function generateACL(pageConfig, componentConfig, roles) {
    const acl = {};

    // Pages
    for (const page in pageConfig) {
      const { roles_enabled = [], roles_disabled = [] } = pageConfig[page];
      let hasAccess = false;
      if (roles.some(r => roles_enabled.includes(r)) && !roles.some(r => roles_disabled.includes(r))) {
        hasAccess = true;
      }
      acl[page] = { hasAccess };
    }

    // Components (if needed)
    for (const comp in componentConfig) {
      const { roles_enabled = [], roles_disabled = [] } = componentConfig[comp];
      let hasAccess = false;
      if (roles.some(r => roles_enabled.includes(r)) && !roles.some(r => roles_disabled.includes(r))) {
        hasAccess = true;
      }
      acl[comp] = { hasAccess };
    }

    return acl;
  }

  /**
   * Sub-function: validate Home URL with hash params and generate ACL
   */
  function home_validate(redirectUrl, pageConfig, componentConfig) {
    const params = parseHashParams(redirectUrl);
    const access_token = params['access_token'] || null;
    const id_token = params['id_token'] || null;
    const roles = params['roles'] ? params['roles'].split(',') : [];

    if (!access_token || !id_token) {
      // Missing tokens, redirect to login
      return {
        access_token: null,
        id_token: null,
        acl: {},
        redirect_url: 'https://example.com/login'
      };
    }

    const acl = generateACL(pageConfig, componentConfig, roles);

    return {
      access_token,
      id_token,
      acl,
      redirect_url: redirectUrl
    };
  }

  /**
   * Main function: validate URL, check for Home & access token
   * @param {string} redirectUrl 
   * @param {Object} pageConfig 
   * @param {Object} componentConfig 
   */
  function validate(redirectUrl, pageConfig, componentConfig) {
    const lowerUrl = redirectUrl.toLowerCase();
    const params = parseHashParams(redirectUrl);

    // Check if URL contains "home" and has access_token
    if ( params['access_token']) {
      return home_validate(redirectUrl, pageConfig, componentConfig);
    } else {
      // Redirect to login if not home or no access_token
      return {
        access_token: null,
        id_token: null,
        acl: {},
        redirect_url: 'https://example.com/login'
      };
    }
  }

  // Expose public API
  return {
    validate
  };
})();
