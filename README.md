# Ransomware Detection and Response System (RDRS)



**Version:** 0.1.0



**Project Type:** Cybersecurity - Ransomware Detection Prototype



## 1. Project Overview



The Ransomware Detection and Response System (RDRS) is a Python-based prototype designed to monitor file-system activity and identify suspicious patterns that may indicate ransomware-like behavior.



The system monitors a specified directory, calculates file entropy, tracks file events, and generates alerts when configured activity thresholds are reached.



## 2. Features



- Real-time file monitoring using Watchdog.

- Shannon entropy calculation.

- Suspicious file detection based on an entropy threshold.

- Monitoring of file creation, modification, and rename events.

- Detection of ransomware-like bursts of file activity.

- Logging of monitoring events and errors.



## 3. Technologies Used



- Python 3.12

- Watchdog

- PyYAML

- Shannon Entropy

- Python Logging



## 4. Project Structure



```text

RDRS/

|-- app/

|   |-- core/

|   |   |-- __init__.py

|   |   |-- config.py

|   |   |-- entropy.py

|   |   |-- file_monitor.py

|   |   |-- logger.py

|   |-- detectors/

|   |   |-- detection_engine.py

|   |-- main.py

|-- config.yaml

|-- data/

|-- logs/

|-- tests/

|-- requirements.txt

|-- README.md

```



## 5. Installation



### Prerequisites



- Python 3.12 or later

- Windows or Linux



### Install dependencies



```bash

pip install -r requirements.txt

```



## 6. Configuration



The system uses `config.yaml` to configure monitoring and detection.



Important settings:



- `watch_directory`: Directory monitored by RDRS.

- `scan_interval`: Configured monitoring interval.

- `entropy_threshold`: Threshold used to flag suspicious files.

- `enable_entropy_detector`: Entropy detector setting.

- `log_directory`: Directory used to store logs.

- `log_level`: Logging level.



## 7. Running the Project



Open a terminal in the project root directory and activate your virtual environment if applicable.



Start the monitoring system:



```bash

python -m app.core.file_monitor

```



Press `CTRL+C` to stop monitoring.



## 8. Testing the System



Open another terminal in the project directory.



Create a test file:



```cmd

echo RDRS testing > data\test_file.txt

```



Modify the file:



```cmd

echo File modification test >> data\test_file.txt

```



Rename the file:



```cmd

ren data\test_file.txt test_file.locked

```



Observe the monitoring terminal for detected events and warnings.



## 9. Log Files



RDRS stores monitoring records in:



```text

logs/rdrs.log

```



The log includes monitoring start and stop messages, file events, entropy values, and errors.



## 10. Detection Method



RDRS uses Shannon entropy to measure the randomness of file contents.



Higher entropy can be associated with encrypted or compressed data. The detection engine also monitors file activity within a configured time window.



A ransomware-like activity alert can be generated when configured thresholds for modifications, renames, extension changes, or high-entropy files are reached.



## 11. Limitations



- Entropy alone cannot confirm ransomware.

- Legitimate compressed or encrypted files may also have high entropy.

- The current prototype monitors and reports suspicious activity.

- Automatic file quarantine, deletion, and recovery are not implemented.

- Detection depends on configured thresholds and observed file-system events.



## 12. Future Enhancements



- File quarantine and isolation.

- Web-based monitoring dashboard.

- Database integration for event history.

- Advanced behavioral detection.

- Email or desktop alert notifications.

- File recovery and response automation.



## 13. Disclaimer



RDRS is an educational cybersecurity prototype developed for learning and demonstration purposes. It is not a replacement for enterprise endpoint protection or a production ransomware prevention solution.

