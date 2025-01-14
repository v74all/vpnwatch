# V7lthronyx VPN Watch

[English](#english) | [فارسی](#persian)

---

<a name="english"></a>
## English Documentation

### Overview
V7lthronyx VPN Watch is a sophisticated VPN security analysis tool designed to detect and assess VPN connections, protocols, and potential security vulnerabilities. The application provides comprehensive scanning and monitoring capabilities for network security professionals.

### Features
- Real-time VPN connection monitoring
- Protocol detection (OpenVPN, WireGuard, L2TP, PPTP, IPSec)
- SSL/TLS security analysis
- Port scanning and vulnerability assessment
- Blacklist checking
- DNS analysis
- Network path tracing
- Operating system detection
- Quantum-resistant encryption support

### Requirements
- Python 3.8+
- PyQt5
- Required Python packages (install via pip):
```bash
pip install -r requirements.txt
```

### Installation
1. Clone the repository:
```bash
git clone https://github.com/v74all/vpnwatch.git
cd vpnwatch
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure API keys in `config.yaml`:
```yaml
api_keys:
  VirusTotal: "YOUR_VIRUSTOTAL_API_KEY"
  AbuseIPDB: "YOUR_ABUSEIPDB_API_KEY"
  # ... other API keys
```

### Usage
1. Start the application:
```bash
python main.py
```

2. Using the GUI:
   - Enter IP address or domain for scanning
   - Select scan type (Quick/Full)
   - View results in real-time
   - Export reports as needed

### Advanced Features
- **Quantum-Resistant Encryption**: Built-in support for post-quantum cryptography
- **Zero Trust Security**: Implements zero trust architecture principles
- **Advanced Monitoring**: Prometheus metrics integration
- **Caching System**: Redis-based result caching for improved performance

### Configuration
Detailed settings can be modified in `config.yaml`:
- API configurations
- Scan settings
- Performance tuning
- Security parameters
- Monitoring options

---

<a name="persian"></a>
## مستندات فارسی

### معرفی
V7lthronyx VPN Watch یک ابزار پیشرفته تحلیل امنیتی VPN است که برای تشخیص و ارزیابی اتصالات VPN، پروتکل‌ها و آسیب‌پذیری‌های امنیتی احتمالی طراحی شده است. این برنامه قابلیت‌های جامع اسکن و نظارت را برای متخصصان امنیت شبکه فراهم می‌کند.

### قابلیت‌ها
- نظارت بر اتصالات VPN در زمان واقعی
- تشخیص پروتکل (OpenVPN، WireGuard، L2TP، PPTP، IPSec)
- تحلیل امنیتی SSL/TLS
- اسکن پورت و ارزیابی آسیب‌پذیری
- بررسی لیست سیاه
- تحلیل DNS
- ردیابی مسیر شبکه
- تشخیص سیستم عامل
- پشتیبانی از رمزنگاری مقاوم در برابر کوانتوم

### پیش‌نیازها
- پایتون 3.8 یا بالاتر
- PyQt5
- بسته‌های پایتون مورد نیاز (نصب از طریق pip):
```bash
pip install -r requirements.txt
```

### نصب
1. کلون کردن مخزن:
```bash
git clone https://github.com/v74all/vpnwatch.git
cd vpnwatch
```

2. نصب وابستگی‌ها:
```bash
pip install -r requirements.txt
```

3. تنظیم کلیدهای API در `config.yaml`:
```yaml
api_keys:
  VirusTotal: "YOUR_VIRUSTOTAL_API_KEY"
  AbuseIPDB: "YOUR_ABUSEIPDB_API_KEY"
  # ... سایر کلیدهای API
```

### نحوه استفاده
1. اجرای برنامه:
```bash
python main.py
```

2. استفاده از رابط گرافیکی:
   - وارد کردن آدرس IP یا دامنه برای اسکن
   - انتخاب نوع اسکن (سریع/کامل)
   - مشاهده نتایج در زمان واقعی
   - خروجی گرفتن از گزارش‌ها در صورت نیاز

### ویژگی‌های پیشرفته
- **رمزنگاری مقاوم در برابر کوانتوم**: پشتیبانی از رمزنگاری پسا-کوانتومی
- **امنیت Zero Trust**: پیاده‌سازی اصول معماری Zero Trust
- **نظارت پیشرفته**: یکپارچه‌سازی با متریک‌های Prometheus
- **سیستم کش**: کش‌کردن نتایج بر پایه Redis برای بهبود کارایی

### پیکربندی
تنظیمات دقیق در `config.yaml` قابل تغییر است:
- تنظیمات API
- تنظیمات اسکن
- تنظیمات کارایی
- پارامترهای امنیتی
- گزینه‌های نظارت

---

### License
MIT License


