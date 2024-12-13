Overview
This project demonstrates how Software Defined Networking (SDN) can be combined with Machine Learning (ML) to detect and mitigate Denial of Service (DoS) attacks. It uses the Ryu SDN Controller to monitor and manage network traffic and employs a Random Forest Classifier for dynamic traffic classification. The system detects malicious sources and blocks them in real time by installing flow rules in the OpenFlow switch.

The project features two implementations:

Static Threshold-Based Model (dos_detection_controller.py): Detects malicious traffic based on predefined thresholds for packet counts and time intervals.
ML-Enhanced Model (dynamic_controller.py): Uses a trained Machine Learning model for adaptive traffic classification, providing better accuracy and reducing false positives.
Features
Real-time traffic monitoring using the Ryu SDN Controller.
Dynamic flow rule installation to block malicious traffic.
Adaptive traffic classification using a Machine Learning model.
Simulated network environment using Mininet and a star topology.
Dependencies and Tools
Environment
Operating System: Ubuntu (recommended)
Python: Version 3.8 (required for Ryu and ML libraries)
VMware: For virtualized development environment (optional but recommended)
Tools
Ryu SDN Controller:

Used for network traffic monitoring and rule enforcement.
Install with:
sudo apt update
sudo apt install python3-ryu

Mininet:

Simulates the network topology.
Install with:
sudo apt install mininet

Python Libraries:

Numpy and scikit-learn: Required for Machine Learning functionalities.
Install with:
pip install numpy scikit-learn

File Descriptions
1. dos_detection_controller.py
This script implements a threshold-based detection system:

Purpose: Detects malicious traffic by monitoring packet counts and time intervals. If traffic exceeds a predefined threshold, it is flagged as malicious, and a drop rule is installed in the switch.

Execution:
ryu-manager /path/to/dos_detection_controller.py
Key Features:
Tracks packets from each source IP.
Flags and blocks sources exceeding the static threshold.
Works well for high-rate attacks but may generate false positives.
2. dynamic_controller.py
This script integrates Machine Learning for adaptive traffic classification:

Purpose: Utilizes a Random Forest Classifier to classify traffic as legitimate or malicious based on packet counts and time intervals.
Execution:

ryu-manager /path/to/dynamic_controller.py
Key Features:
Dynamically adapts to traffic patterns using ML predictions.
Reduces false positives compared to the threshold-based model.
Automatically blocks malicious sources by installing drop rules in the switch.

3. star_topology.py
This script defines a star topology in Mininet:

Purpose: Simulates a network with a single switch and multiple hosts connected in a star formation.
Execution:
sudo python3 /path/to/star_topology.py

Key Features:
Creates a topology with a configurable number of hosts.
Forwards traffic to the controller for inspection.
Commands to Execute the Code

Step 1: Set Up the Topology
Run the topology script to create a star topology:
sudo python3 /path/to/star_topology.py

Step 2: Run the Ryu Controller
Start the desired controller (static or ML-based):

For the threshold-based controller:
ryu-manager /path/to/dos_detection_controller.py

For the ML-based controller:
ryu-manager /path/to/dynamic_controller.py
Step 3: Simulate Network Traffic
In the Mininet CLI, generate traffic from a host to simulate a DoS attack:

hping3 -S -p 80 --flood <target-IP>
Replace <target-IP> with the IP address of the target host.

Future Scope
This project can be extended in several ways:

Implement detection of distributed denial of service (DDoS) attacks by incorporating distributed traffic patterns.
Add real-time retraining of the ML model using live network data to handle evolving attack methods.
Scale the system for larger, multi-layered networks with multiple controllers.
Introduce visualization tools for better real-time monitoring and analysis of network activity.
Contributing
Contributions are welcome! If you have ideas or improvements, feel free to fork the repository and submit a pull request or open an issue.

