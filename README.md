# Network Analyzer

### [click here for documentation and guide](https://guang84.github.io/projects/?id=network-analyzer-v2026)

Network Analyzer is a Linux terminal application for authorized wireless assessment, local monitoring, scan reporting, and investigation of unusual wireless behavior.

The 2026.08.21 architecture moves command dispatch into Python while keeping the Bash launcher focused on environment preparation. The application stores scans, reports, logs, learned patterns, incidents, and locally trained anomaly models on the operator's machine.

> Use only on networks, devices, and radio spectrum you own or are explicitly authorized to assess. Active features may interrupt wireless service.

## Quick start

```bash
chmod +x network_analyzer.sh
./network_analyzer.sh
```