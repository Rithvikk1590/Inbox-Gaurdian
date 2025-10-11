# Inbox-Gaurdian
A hybrid rule-based algortihm to help users determine if an uploaded email is phising or ham

## Features
- Detects phishing emails based on predefined rules
   - Whitelist checker
   - Keyword Detector
   - Position Scorer
   - Edit Distance
   - URL Analyzer
   - Attachment Checker
- Machine Learning Algorithm

## Installation

To set up and run the project locally, follow these steps:

### 1. Clone the repository:
```bash
git clone https://github.com/Rithvikk1590/Inbox-Guardian.git
```

### 2. (OPTIONAL) Create Virtual Environment 
It's recommended to use a virtual environment to isolate dependencies:

```bash
python -m venv env
```
### Windows:
```bash
env\\Scripts\\activate
```
### macOS/Linux:
```bash
source env/bin/activate
```

### 3. Install Dependencies
Install required packages from requirements.txt:
```bash
pip install -r requirements.txt
```
### 4. Run the application
```bash
cd Website
python app.py
```
