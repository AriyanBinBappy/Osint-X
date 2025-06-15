# 🛠️ Octo Dark Cyber Squad Osint-X

**Author:** Ariyan Bin Bappy  
**Group:** Octo Dark Cyber Squad  
**Purpose:** Authorized OSINT tool for extracting and managing media metadata

---

## Overview

`Osint-X` is a Python utility designed to extract, view, remove, and export metadata from images and videos. It supports a wide range of media formats and offers batch processing capabilities for folder-wide metadata extraction into CSV reports, making it ideal for OSINT investigations, digital forensics, and media analysis.

---

## Features

- View metadata (EXIF, GPS, camera info, hashes) for single media files  
- Remove metadata securely to protect privacy  
- Export metadata to text files  
- Batch process entire folders and export CSV reports with GPS data  
- Calculate MD5 and SHA-256 hashes for integrity verification  
- Support for popular image and video formats including RAW files  
- Converts GPS data to decimal degrees and provides Google Maps links  
- Simple command-line interface  
- Results saved automatically to `saved_media/` folder  

---

## Supported Formats

**Images:**  
`.jpg`, `.jpeg`, `.png`, `.tiff`, `.bmp`, `.gif`, `.heic`, `.arw`, `.cr2`, `.nef`

**Videos:**  
`.mp4`, `.mov`, `.avi`, `.mkv`, `.3gp`, `.wmv`, `.flv`, `.mts`, `.mxf`

---

## Installation

1. Clone the repository:

    ```bash
    git clone https://github.com/yourusername/osint-x.git
    cd osint-x
    ```

2. Install Python dependencies:

    ```bash
    pip install pyexiftool
    ```

3. Install **ExifTool**:

    - Download from [ExifTool official site](https://exiftool.org/)  
    - Ensure `exiftool` is available in your system PATH

---

## Usage

Run the script:

```bash
python osint_x.py
