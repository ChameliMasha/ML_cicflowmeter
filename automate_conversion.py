# server.py
import os
import subprocess
import pandas as pd
from flask import Flask, request, jsonify
from feed_to_ml import model_feed
import ipaddress
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import pickle
import tensorflow as tf
import numpy as np


app = Flask(__name__)

columns_to_keep = ['src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'flow_duration', 'tot_fwd_pkts', 'tot_bwd_pkts',
                   'totlen_fwd_pkts', 'totlen_bwd_pkts', 'flow_byts_s', 'flow_pkts_s', 'fwd_iat_std', 'bwd_iat_std', 
                   'fwd_pkts_s', 'bwd_pkts_s', 'pkt_len_min', 'pkt_len_max', 'pkt_len_std', 'fin_flag_cnt', 'syn_flag_cnt', 
                   'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt', 'urg_flag_cnt', 'cwr_flag_count', 'down_up_ratio']

def convert_pcap_to_csv(pcap_file, output_dir):
    try:
        csv_output = os.path.join(output_dir, "output.csv")
        pcap_file = os.path.abspath(pcap_file)
        csv_output = os.path.abspath(csv_output)

        # Command to execute cicflowmeter
        command = ['cicflowmeter', '-f', pcap_file, '-c', csv_output, '-v']
        
        # Running the command using subprocess
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Return anomalies from filtering process
            return filter_columns(csv_output, output_dir)
        else:
            return {"message": f"Error occurred: {result.stderr}", "anomalies": -1}
            
    except Exception as e:
        return {"message": f"An error occurred: {str(e)}", "anomalies": -1}


def filter_columns(input_file, output_dir):
    output_file = os.path.join(output_dir, "output_filtered.csv")
    data = pd.read_csv(input_file)
    filtered_data = data[columns_to_keep]
    filtered_data.to_csv(output_file, index=False)
    
    no_of_anomalies = model_feed(output_file)
    print(f"no of anomalies: ", no_of_anomalies)
     
     # Return the result
    return {"message": "Successfully converted", "anomalies": no_of_anomalies}

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'status': 'error', 'message': 'No file part in the request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'status': 'error', 'message': 'No selected file'}), 400

    if file:
        file_path = os.path.join('./uploads', file.filename)
        file.save(file_path)

        output_dir = './outputs'
        os.makedirs(output_dir, exist_ok=True)

        # Get status message and anomalies count
        result = convert_pcap_to_csv(file_path, output_dir)

        # Ensure any np.int64 is converted to a regular Python int before returning
        anomalies_count = int(result['anomalies']) if isinstance(result['anomalies'], (np.integer, np.int64)) else result['anomalies']

        return jsonify({'status': 'success', 'message': result['message'], 'anomalies': anomalies_count})

if __name__ == '__main__':
    os.makedirs('./uploads', exist_ok=True)
    app.run(host='0.0.0.0', port=5000)