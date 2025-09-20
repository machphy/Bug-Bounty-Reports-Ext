# Report Extractor

<img width="979" height="360" alt="image" src="https://raw.githubusercontent.com/machphy/Bug-Bounty-Reports-Ext/refs/heads/main/image.png" />

A small CLI tool that fetches **resolved & disclosed** HackerOne reports by vulnerability (CWE/keyword) and exports them to a CSV file.  
Includes a lightweight ASCII banner, spinner, and colorized terminal output.

---

## ✨ Features
- Query HackerOne via GraphQL (search by vulnerability/CWE)
- Pagination support (fetch up to **3000 reports** per run)
- Export results to CSV (`Title | Severity | URL`)
- Animated banner + spinner and colorized report printing
- Minimal dependencies

---

## 🛠 Requirements
- Python **3.7+**
- Packages: `requests`, `pyfiglet`

---

## 📦 Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/machphy/Bug-Bounty-Reports-Ext.git
   cd Bug-Bounty-Reports-Ext
