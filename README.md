# Honet

Honet: Home network montitor is a scheduled network scanner for complete visibility on your home network.

# Tech Stack

    - Python 3.12.3
    - Streamlit 1.55.0
    - Sqlite 3.45.1
    - Nmap 7.94SVN

# Development PLatform
    - Ubuntu 24.04.3 LTS (Noble Numbat)

# How To Run?

    - Execute the commands below:
        1. "python3 -m venv .venv"
        2. "source /venv/bin/activate"
        3. "cd Honet"
        4. "pip install -r requirements.txt"
        5. "streamlit run streamlit.py"
        6. Navigate to your browser and try to access servers 8501 port.

# Improvments (Not Scheduled)
    - SSL support,
    - Bash script for installation,
    - Docker support (designed for rpi zero w development card, it requires 1 core CPU and 500 MB max. So you can just run it anywhere),
    - Log and db export.
