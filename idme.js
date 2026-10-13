$(function() {
  var IDme = {
    defaultBaseUrl: "https://api.id.me",
    widgetUrl: "https://s3.amazonaws.com/idme/developer/idme-buttons/assets/js/idme-wallet-button.js",
    button: document.getElementById("idme-wallet-button"),
    response: new URLSearchParams(window.location.hash.slice(1)),

    // ?idme_base_url= overrides data-base-url, but only for a local mock
    baseUrl: function() {
      var override = new URLSearchParams(window.location.search).get("idme_base_url");
      var url = override && /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/?$/.test(override) ? override : this.button.getAttribute("data-base-url");
      return (url || this.defaultBaseUrl).replace(/\/$/, "");
    },

    isMock: function() {
      return this.baseUrl() !== this.defaultBaseUrl;
    },

    redirectUri: function() {
      var redirect = this.button.getAttribute("data-redirect");
      return /^https?:\/\//.test(redirect) ? redirect : window.location.origin + window.location.pathname + window.location.search;
    },

    showMessage: function(text) {
      $("#idme-message").text(text);
    },

    // The hosted button always targets api.id.me, so mock mode renders a plain link to the mock instead
    renderButton: function() {
      if (!this.button) return;

      if (this.isMock()) {
        var params = new URLSearchParams({
          client_id: this.button.getAttribute("data-client-id"),
          redirect_uri: this.redirectUri(),
          response_type: this.button.getAttribute("data-response") || "token",
          scope: this.button.getAttribute("data-scope"),
          op: this.button.getAttribute("data-op") || "signin"
        });
        var container = $("<span id='idme-verification'></span>");
        container.append($("<span class='idme-text'></span>").text(this.button.getAttribute("data-text") || ""));
        container.append("<br>");
        container.append($("<a id='idme-mock-button'>Verify with ID.me (mock)</a>").attr("href", `${this.baseUrl()}/oauth/authorize?${params}`));
        $(this.button).replaceWith(container);
        return;
      }

      var button = this.button;
      var script = document.createElement("script");
      script.src = this.widgetUrl;
      // the widget binds on DOMContentLoaded, which has already fired by the time this runs
      script.onload = function() {
        if (document.body.contains(button) && window.BindIDme) window.BindIDme();
      };
      document.body.appendChild(script);
    },

    request: function() {
      var self = this;
      var accessToken = this.response.get("access_token");
      var error = this.response.get("error");

      if (error) {
        this.showMessage(`ID.me verification failed: ${this.response.get("error_description") || error}`);
        this.renderButton();
        return;
      }

      if (!accessToken) {
        this.renderButton();
        return;
      }

      history.replaceState(null, "", window.location.pathname + window.location.search);

      fetch(`${this.baseUrl()}/api/public/v3/attributes.json?access_token=${encodeURIComponent(accessToken)}`).then(function(response) {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      }).then(function(data) {
        console.log(data);
        var status = (data.status || [])[0];
        if (!status || !status.verified) throw new Error("not verified");

        var fname = (data.attributes || []).filter(function(attribute) { return attribute.handle === "fname"; })[0] || data.attributes[0];
        self.showMessage(`Thank you ${fname.value} for verifying your ${status.subgroups[0]} status with ID.me.`);
      }).catch(function(err) {
        console.log("ID.me attributes request failed", err);
        self.showMessage("We couldn't confirm your verification status with ID.me. Please try again.");
        self.renderButton();
      });
    }
  };

  IDme.request();
});
