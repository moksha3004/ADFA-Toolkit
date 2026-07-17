# 🔍 Advanced Digital Forensics & Anti-Forensics Detection Toolkit (ADFA)

> M.Sc. Major Project – Rashtriya Raksha University

A web-based digital forensics toolkit designed to assist investigators in analyzing digital evidence, detecting anti-forensic techniques, and generating comprehensive forensic investigation reports.

## Features

- 📄 Metadata Analysis
  - EXIF metadata extraction
  - File hashing (MD5 & SHA-256)
  - Timestamp anomaly detection using MFT artifacts

- 🖼️ Steganography Detection
  - Image analysis
  - Video analysis
  - Entropy analysis
  - LSB detection

- 📁 File Signature Detection
  - File header verification
  - Extension mismatch detection

- 🔐 Encoding & Decoding
  - Base32
  - Base64

- 🤖 Deepfake Detection
  - Image analysis
  - Video analysis

- 📊HTML Report Generation
  - Interactive HTML forensic reports 
  - Detailed investigation summaries 
  - Exportable forensic analysis results

---

## Tech Stack

- Python
- Flask
- HTML5
- CSS3
- JavaScript
- NumPy
- OpenCV
- Pillow
- Transformers (Hugging Face)
- PyTorch

---

## Project Structure

```
ADFA-Toolkit/
│
├── app.py
├── run.py
├── requirements.txt
├── README.md
├── templates/
├── static/
├── tools/
└── .gitignore
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/moksha3004/ADFA-Toolkit.git
cd ADFA-Toolkit
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python run.py
```

Open your browser:

```
http://localhost:5050
```

---

## Sample Workflow

1. Upload a file for forensic analysis.
2. Select the required analysis module.
3. Run the selected forensic analysis module.
4. Review the findings.
5. Generate an interactive HTML forensic investigation report.

---

## Tools & Technologies

- Flask
- OpenCV
- NumPy
- Pillow
- Exif Library (Python)
- ExifTool (Optional)
- HTML/CSS/JavaScript

---

## Future Enhancements

- Memory Forensics
- Windows Registry Analysis
- Browser Artifact Analysis
- Timeline Analysis
- AI-assisted Malware Detection

---

## Author

**Moksha Shroff**

M.Sc. Cyber Security & Digital Forensics

Rashtriya Raksha University

---

## Disclaimer

This project was developed for academic and educational purposes as part of a Master's degree project. It is intended to demonstrate digital forensic analysis techniques and should be used responsibly in accordance with applicable laws and organizational policies.

---
## License

This project is licensed under the MIT License. See the LICENSE file for details.