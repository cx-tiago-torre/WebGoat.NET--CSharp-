# Using older vulnerable Windows base images with known CVEs
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2019

# Add some vulnerable components and packages
RUN powershell -Command \
    # Install vulnerable version of IIS URL Rewrite Module (has CVE-2023-36899)
    Invoke-WebRequest -Uri 'https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi' -OutFile 'c:\rewrite.msi'; \
    Start-Process msiexec.exe -ArgumentList '/i', 'c:\rewrite.msi', '/quiet', '/norestart' -Wait; \
    Remove-Item 'c:\rewrite.msi'

# Set working directory
WORKDIR /inetpub/wwwroot

# Copy the application files
COPY WebGoat/ .

# Create a vulnerable configuration with hardcoded secrets
RUN powershell -Command \
    # Create a vulnerable web.config with hardcoded secrets
    echo '<configuration><connectionStrings><add name=\"DefaultConnection\" connectionString=\"Server=sql-server;Database=WebGoat;User Id=sa;Password=StrongP@ssw0rd123;\" /></connectionStrings></configuration>' > vulnerable-secrets.config

# Expose port 80
EXPOSE 80

# Use vulnerable startup script
CMD ["powershell", "-Command", "Start-Service W3SVC; while ($true) { Start-Sleep -Seconds 3600 }"]

# Multi-stage build to include additional vulnerable images
FROM ubuntu:18.04 as vulnerable-tools
# Ubuntu 18.04 has multiple known CVEs

# Install vulnerable versions of common tools
RUN apt-get update && apt-get install -y \
    # OpenSSL with known vulnerabilities
    openssl=1.1.1-1ubuntu2.1~18.04.23 \
    # Git with CVE-2022-24765
    git=1:2.17.1-1ubuntu0.17 \
    # Curl with multiple CVEs
    curl=7.58.0-2ubuntu3.24 \
    # Python with known vulnerabilities
    python2.7=2.7.17-1~18.04ubuntu1.11 \
    # Node.js vulnerable version
    nodejs=8.10.0~dfsg-2ubuntu0.4 \
    npm=3.5.2-0ubuntu4 \
    && rm -rf /var/lib/apt/lists/*

# Install vulnerable npm packages
RUN npm install -g \
    # Lodash with prototype pollution vulnerability
    lodash@4.17.15 \
    # Express with multiple vulnerabilities
    express@4.16.4 \
    # Moment.js with ReDoS vulnerability
    moment@2.24.0

# Copy some vulnerable scripts
COPY <<EOF /vulnerable-script.sh
#!/bin/bash
# Vulnerable bash script with command injection
echo "Running command: \$1"
eval \$1
EOF

RUN chmod +x /vulnerable-script.sh

# Final stage - combine everything
FROM mcr.microsoft.com/dotnet/framework/aspnet:4.8-windowsservercore-ltsc2019

# Copy vulnerable tools from previous stage
COPY --from=vulnerable-tools /usr/bin/curl /tools/
COPY --from=vulnerable-tools /vulnerable-script.sh /tools/

WORKDIR /inetpub/wwwroot
COPY WebGoat/ .

# Add hardcoded secrets in environment variables (another vulnerability)
ENV DB_PASSWORD="SuperSecret123!"
ENV API_KEY="sk-proj-1234567890abcdef1234567890abcdef1234567890abcdef"
ENV JWT_SECRET="jwt-secret-key-that-should-not-be-hardcoded-here"
ENV ADMIN_PASSWORD="admin"

EXPOSE 80

CMD ["powershell", "-Command", "Start-Service W3SVC; while ($true) { Start-Sleep -Seconds 3600 }"]