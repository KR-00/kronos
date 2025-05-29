
# Kronos – Automated Web Vulnerability Detection Tool

Kronos is a Python-based automated scanning tool designed for detecting vulnerabilities in web applications. In this version it features a graphical user interface, a behaviour-based detection engine, and an optional crawler for endpoint discovery. This tool is intended for use in controlled lab environments for educational purposes.

## Environment Setup

Kronos was tested inside a virtual machine running **Kali Linux** (Debian-based) using VMware Workstation. 

**System specifications:**
- **OS**: Kali Linux (Debian 12.x 64-bit)
- **Virtualization**: VMware Workstation Pro
- **RAM**: 8 GB
- **CPUs**: 8 cores
- **Disk Size**: 40 GB
- **Network Mode**: NAT

**The above specifications are not requirements.**

## Installation 


### 1. Installing Chrome and Chromedriver

Before running Kronos, make sure Google Chrome and the matching ChromeDriver are installed.

**Chrome & ChromeDriver Setup (Required for Selenium)**

To install Google chrome run those commands in the terminal:

```bash
sudo apt update
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```

Take note of the version number:

```bash
google-chrome --version
```

**Download and Install the Matching ChromeDriver**

1. **To Download it via the command line(Recommendend):**

Replace the version in the link below with your Chrome version:

```bash
wget https://edgedl.me.gvt1.com/edgedl/chrome/chrome-for-testing/114.0.5735.90/linux64/chromedriver-linux64.zip
unzip chromedriver-linux64.zip
chmod +x chromedriver-linux64/chromedriver
sudo mv chromedriver-linux64/chromedriver /usr/local/bin/
```

2. **To Download it manually:**

Go to [Chrome for Testing - Availability](https://googlechromelabs.github.io/chrome-for-testing/)

Download the ChromeDriver that matches your Chrome version.

Extract it, then run:

```bash
chmod +x chromedriver
sudo mv chromedriver /usr/local/bin/
```

### 2. Clone the Repository

Open a terminal and run:

```bash
git clone https://github.com/KR-00/kronos.git
cd kronos
```

### 3. Installing dependecies

**Before running Kronos, it is recommended to install dependencies inside a virtual environment.**

```bash
python3 -m venv venv
source venv/bin/activate
```

**Then install the required Python packages:**

```bash
pip install -r requirements.txt
```

**Now you can run :**

```bash
python3 main.py
```

**To start Kronos**

### 4. Download Docker

Kronos was tested on vulnerable web applications such as OWASP Juice Shop, DVWA, and Mutillidae II. 

To download Docker in the terminal run:

```bash
sudo apt update
sudo apt install -y docker.io
sudo systemctl start docker
sudo systemctl enable docker
```

**(Optional but recommended): Add your user to the Docker group so you can run Docker without sudo:**

```bash
sudo usermod -aG docker $USER
```

**You must log out and log back in (or reboot) for this change to take effect.**

To stop all containers after testing:

```bash
docker stop $(docker ps -q)
```

### 5. Running Vulnerable Web Applications via Docker

We will be using pre-built images for the following applications:

**OWASP Juice Shop** (The scan takes longer due to heavy use of javascript, pop ups and more)

**DVWA (Damn Vulnerable Web Application)**

**Mutillidae II**

The following commands will download and start each application in a container.

Each command uses the format:

```bash
docker run -d -p <host_port>:<container_port> <image_name>
```
**The format host:container means your local system can access the app at localhost:host**

You can change the host port if the default is already in use.

**A. OWASP Juice Shop**

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
```

Access it at: http://localhost:3000/#/

**B. DVWA (Damn Vulnerable Web Application)**

```bash
docker run -d -p 8080:80 vulnerables/web-dvwa
```

Access it at: http://localhost:8080

**C. Mutillidae II**

```bash
docker run -d -p 8888:80 citizenstig/nowasp
```

Access it at: http://localhost:8888

## USage 

Once Kronos is running, use the GUI to:

- Enter a target URL (e.g., `http://localhost:3000/#/`)
- Choose a payload category or load a custom payload list
- Start scanning
- (Optional) Enable email alerts for anomaly detection (Requires gmail app password)

## Testing

During testing, Kronos was used to scan selected pages from the following vulnerable applications:

OWASP Juice Shop
**/#/login: Login page tested for authentication bypass via SQLi**

Damn Vulnerable Web Application (DVWA)
**/vulnerabilities/sqli/: Classic SQL Injection test page (Using Authenticated Scanning with credentials: admin:password)**

Mutillidae II
**index.php?page=login.php: Login form scanned for classic SQLi**

## License

This tool is intended for **educational and research purposes only**. Use it only in **authorized testing environments**. The author is not responsible for misuse.
