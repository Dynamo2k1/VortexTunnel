---

# 🚀 Advanced Python Proxy (HTTP/S, TLS, DoH, Logging)  

![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg?style=flat&logo=python)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Status](https://img.shields.io/badge/Status-Active-success)  
![Contributions](https://img.shields.io/badge/Contributions-Welcome-brightgreen.svg)  

## 🌟 Overview  
This **Advanced Python Proxy** is a high-performance TCP/HTTP(S) proxy with **TLS support, DNS over HTTPS (DoH), rotating User-Agents, logging, and header modification** to simulate real browser traffic. Designed for **security research, penetration testing, and network analysis**, it provides deep traffic inspection and protocol handling.  

🔹 **Key Features:**  
✔️ **HTTP & HTTPS Support** – Handles HTTP traffic and HTTPS tunnels via `CONNECT`.  
✔️ **TLS & SSL Handling** – Configurable TLS context with strong cipher suites.  
✔️ **Rotating User-Agents** – Mimics modern browsers to bypass bot detection.  
✔️ **DNS over HTTPS (DoH)** – Resolves domains securely via Cloudflare.  
✔️ **Traffic Logging** – Saves intercepted requests and responses for analysis.  
✔️ **Customizable Handlers** – Modify requests and responses dynamically.  
✔️ **Multi-Threaded & Scalable** – Handles multiple clients efficiently.  

---

## 📌 Installation  

### 🔹 Prerequisites  
Ensure you have **Python 3.8+** installed. Then, install dependencies:  

```bash
pip install dnspython
```

### 🔹 Clone the Repository  
```bash
git clone https://github.com/Dynamo2k1/VortexTunnel.git
cd advanced-python-proxy
```

---

## 🛠 Usage  

### 🔹 Basic Proxy Execution  
Run the proxy server with default settings:  

```bash
python proxy.py 127.0.0.1 8080 example.com 80
```

### 🔹 Enable HTTPS Proxying  
To tunnel HTTPS traffic, use:  
```bash
python proxy.py 127.0.0.1 8080 example.com 443 --ssl
```

### 🔹 Use DNS over HTTPS (DoH)  
To enable **secure DNS resolution**, run:  
```bash
python proxy.py 127.0.0.1 8080 example.com 80 --doh
```

### 🔹 Save Traffic Logs  
To store all request/response logs in a file:  
```bash
python proxy.py 127.0.0.1 8080 example.com 80 --save-log traffic.log
```

### 🔹 Rotate User-Agent Headers  
Bypass bot detection by enabling **randomized User-Agent headers**:  
```bash
python proxy.py 127.0.0.1 8080 example.com 80 --rotate-ua
```

---

## ⚙️ Command-Line Options  

| Option            | Description |
|------------------|------------|
| `local_host` | Local host to listen on. |
| `local_port` | Port to listen on. |
| `remote_host` | Target server host. |
| `remote_port` | Target server port. |
| `--ssl` | Enable TLS/SSL for remote connections. |
| `-i, --insecure` | Disable SSL verification (not recommended). |
| `-s, --save-log <file>` | Save intercepted traffic to a log file. |
| `-r, --rotate-ua` | Enable rotating User-Agent headers. |
| `-d, --doh` | Use DNS over HTTPS (DoH) for domain resolution. |
| `-v, --verbose` | Enable detailed debug logging. |

---

## 🔧 Configuration  

### 🔹 Modify Headers  
You can customize headers in `proxy.py` inside `modify_headers()`:

```python
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.5735.198 Safari/537.36"
]

EXTRA_HEADERS = {
    "Accept": "text/html,application/xhtml+xml",
    "Connection": "keep-alive"
}
```

### 🔹 TLS Cipher Suites  
Modify TLS cipher suites in `get_tls_context()` if needed:

```python
context.set_ciphers(
    "ECDHE-ECDSA-AES128-GCM-SHA256:"
    "ECDHE-RSA-AES128-GCM-SHA256:"
    "ECDHE-ECDSA-AES256-GCM-SHA384:"
    "ECDHE-RSA-AES256-GCM-SHA384"
)
```

---

## 🛡️ Security Considerations  

✅ **Ethical Use Only** – This proxy is for **research and educational purposes**.  
❌ **No Illegal Activities** – Do not use for unauthorized access, MITM attacks, or surveillance.  
🛠 **Logging & Encryption** – Modify logs to prevent storing sensitive data.  

---

## 📜 License  
This project is licensed under the **MIT License** – feel free to modify and distribute responsibly.  

---

## 💡 Contributing  
🔹 Fork the repo & create a new branch.  
🔹 Improve security, add new features, or optimize code.  
🔹 Submit a **Pull Request** with detailed explanations.  

---

## 📬 Contact  
📧 **Email:** dynamo89247@gmail.com 

---

**⚡ Star this repo if you found it useful! 🚀**  

[![GitHub Stars](https://img.shields.io/github/stars/dynamo2k1/VortexTunnel.svg?style=social)](https://github.com/Dynamo2k1/VortexTunnel)  

---
