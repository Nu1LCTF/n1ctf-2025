FROM tomcat:9.0.108-jdk17-temurin

# Enable the RewriteValve so query params can be copied into paths.
RUN set -eux; \
    sed -i 's#</Host>#  <Valve className="org.apache.catalina.valves.rewrite.RewriteValve" />\n  </Host>#' /usr/local/tomcat/conf/server.xml

# Provide the vulnerable rewrite rule that forwards the user supplied path parameter.
RUN set -eux; \
    mkdir -p /usr/local/tomcat/conf/Catalina/localhost; \
    cat <<'REWRITE' > /usr/local/tomcat/conf/Catalina/localhost/rewrite.config
RewriteCond %{QUERY_STRING} (^|&)path=([^&]+)
RewriteRule ^/download$ /%2 [B,L]
REWRITE

COPY start.sh /start.sh
RUN chmod +x /start.sh
# Remove the default ROOT app so the custom WAR becomes the root context.
RUN set -eux; \
    rm -rf /usr/local/tomcat/webapps/*

# Deploy the provided application at the root context.
COPY n1cat.war /usr/local/tomcat/webapps/ROOT.war
EXPOSE 8080

# Keep the default startup command from the base Tomcat image.
CMD ["/start.sh"]
