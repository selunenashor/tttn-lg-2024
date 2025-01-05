import json

def process_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:
            # Parse the JSON data from the line
            data = json.loads(line)
            
            # Extract the required fields
            src_mac = data.get("mac.saddr.str")
            dst_mac = data.get("mac.daddr.str")
            src_ip = data.get("ip.src")
            dst_ip = data.get("ip.dst")
            proto = data.get("ip.protocol")
            
            # Print the extracted fields
            print({
                'src_mac': src_mac,
                'dst_mac': dst_mac,
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'proto': proto
            })

# Example usage: replace 'your_file.json' with the path to your file
process_file('/var/log/custom.json')
