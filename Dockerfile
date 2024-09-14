# Use an official Node.js runtime as a parent image
FROM node:18

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy the package.json and package-lock.json (if available)
COPY package*.json ./

# Install dependencies
RUN npm install

# Install VSCode extensions dependencies
RUN npm install -g @vscode/vsce

# Install any additional dependencies here
# For example, if you need ffuf, nikto, etc., add them
RUN apt-get update && \
    apt-get install -y \
    ffuf \
    nikto \
    nmap \
    gobuster \
    sslyze \
    wpscan \
    sqlmap \
    whatweb \
    theharvester \
    hydra \
    traceroute \
    && rm -rf /var/lib/apt/lists/*

# Copy the rest of your application code
COPY . .

# Install the VSCode extension
RUN vsce package

# Expose any ports if needed (e.g., for testing or debugging)
EXPOSE 8080

# Define the default command to run your application
CMD ["npm", "start"]
