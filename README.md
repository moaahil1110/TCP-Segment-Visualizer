# TCP Segment Visualizer with RTT and Timeout Analysis 🚀
*An interactive tool to analyze TCP behavior from Wireshark captures*

[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#) [![Version](https://img.shields.io/badge/version-1.0-blue.svg)](#)

## Table of Contents
- [Description](#description)
- [Features](#features)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installation Commands](#installation-commands)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Contribution](#contribution)
- [License](#license)

## Description
TCP Segment Visualizer is a Python-based tool that enables users to upload Wireshark capture files (`.pcap`/`.pcapng`) and analyze TCP segments. It extracts key metrics such as Round-Trip Time (RTT), Timeout Intervals, and Receiver Window (RWND) values. The tool provides dynamic graphs and a detailed TCP header table to help users understand the behavior of TCP segments in their network captures.

## Features
- **Import** Wireshark `.pcap`/`.pcapng` files for analysis
- **Extract** and display detailed TCP headers
- **Compute** and plot Round-Trip Time (RTT)
- **Track** timeout intervals and RWND changes over time
- **Interactive GUI** built with Tkinter

## Installation

### Prerequisites
- Python 3.7 or higher
- [Wireshark](https://www.wireshark.org/) (to capture and generate `.pcap` files)
- Required Python modules:
  - `pyshark`
  - `pandas`
  - `matplotlib`
  - `tkinter` (usually bundled with Python)

### Installation Commands
```bash
pip install pyshark pandas matplotlib
```

## Usage
1. Run the Application:
   ```bash
   python your_script.py
   ```
2. Select a Capture File: Use the GUI to browse and select a `.pcap` or `.pcapng` file.
3. View Analysis:

    The application displays:
   
    -A table of TCP headers (including RTT values)
    -Graphs for RTT, Timeout Intervals, CWND changes, and RWND changes
