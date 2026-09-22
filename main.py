import os
import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

def parse_logs():
    ssh_data = []
    apache_data = []

    # Parse SSH Logs
    if os.path.exists('Logs/sample_auth.log'):
        with open('Logs/sample_auth.log', 'r') as f:
            for line in f:
                if 'Failed password' in line:
                    ip = re.search(r'from (\d+\.\d+\.\d+\.\d+)', line)
                    if ip:
                        ssh_data.append({'IP': ip.group(1), 'Event': 'Failed SSH Login'})

    # Parse Apache Logs
    if os.path.exists('Logs/sample_access.log'):
        with open('Logs/sample_access.log', 'r') as f:
            for line in f:
                ip = line.split(' ')[0]
                apache_data.append({'IP': ip, 'Event': 'HTTP Request'})

    return pd.DataFrame(ssh_data), pd.DataFrame(apache_data)

def analyze_and_report():
    print("=== LOG ANALYZER & INTRUSION DETECTION ENGINE ===")
    ssh_df, apache_df = parse_logs()

    # Detect SSH Brute Force
    if not ssh_df.empty:
        brute_force = ssh_df['IP'].value_counts()
        suspicious_ssh = brute_force[brute_force >= 3].reset_index()
        suspicious_ssh.columns = ['IP', 'Failed_Attempts']
        suspicious_ssh['Threat'] = 'SSH Brute-Force Suspect'
        print("\n[!] SUSPICIOUS SSH ACTIVITIES DETECTED:")
        print(suspicious_ssh)
        suspicious_ssh.to_csv('Reports/incident_report.csv', index=False)

    # Visualization
    if not apache_df.empty:
        plt.figure(figsize=(8, 4))
        sns.countplot(data=apache_df, x='IP', palette='Reds_d')
        plt.title('Network Traffic by IP Address')
        plt.xlabel('IP Address')
        plt.ylabel('Request Count')
        plt.tight_layout()
        plt.savefig('Reports/ip_traffic_distribution.png')
        print("\n[+] Visual Report Saved to 'Reports/ip_traffic_distribution.png'")

if __name__ == '__main__':
    analyze_and_report()