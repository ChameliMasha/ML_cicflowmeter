import ipaddress
import pandas as pd
from tensorflow.keras.models import load_model
from sklearn.preprocessing import StandardScaler
import pandas as pd
from sklearn.preprocessing import MinMaxScaler
import pickle
import tensorflow as tf
import numpy as np
# Min-Max Scaling

# Step 1: Load the trained Keras model
# Load the model model
def model_feed(csv_file_path):
    model = load_model('./models/autoencoder_old.h5')

    # Load the threshold value from the pickle file
    with open('./models/threshold-autoencoder_old.pkl', 'rb') as f:
        threshold = pickle.load(f)

    # Step 2: Load the CSV file with the required columns
    # csv_file_path = './outputs/output_filtered.csv'
    data = pd.read_csv(csv_file_path)


    # Convert IP addresses to integers
    data['src_ip'] = data['src_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))
    data['dst_ip'] = data['dst_ip'].apply(lambda x: int(ipaddress.IPv4Address(x)))

    new_column_names = [
    'Src_IP',
    'Src_Port',
    'Dst_IP',
    'Dst_Port',
    'Protocol',
    'Flow_Duration',
    'Tot_Fwd_Pkts',
    'Tot_Bwd_Pkts',
    'TotLen_Fwd_Pkts',
    'TotLen_Bwd_Pkts',
    'Flow_Byts/s',
    'Flow_Pkts/s',
    'Fwd_IAT_Std',
    'Bwd_IAT_Std',
    'Fwd_Pkts/s',
    'Bwd_Pkts/s',
    'Pkt_Len_Min',
    'Pkt_Len_Max',
    'Pkt_Len_Std',
    'FIN_Flag_Cnt',
    'SYN_Flag_Cnt',
    'RST_Flag_Cnt',
    'PSH_Flag_Cnt',
    'ACK_Flag_Cnt',
    'URG_Flag_Cnt',
    'CWE_Flag_Count',
    'Down/Up_Ratio',
    ]

    # Update the DataFrame's column names
    data.columns = new_column_names


    min_max_scaler = MinMaxScaler()
    data = pd.DataFrame(min_max_scaler.fit_transform(data), columns=data.columns)

    # Calculate reconstruction error on the test set
    reconstructions = model.predict(data)
    reconstruction_error = tf.keras.losses.mse(data, reconstructions)

    # Set a threshold for anomaly detection
    # threshold = np.mean(reconstruction_error) + 3 * np.std(reconstruction_error)

    print(f"Threshold for anomaly detection: {threshold}")

    # Evaluate model using the reconstruction error
    # Anomalies are where the reconstruction error is greater than the threshold
    anomalies = reconstruction_error > threshold
    num_anomalies = np.sum(anomalies)
    print(f"Number of anomalies detected: {num_anomalies}")
    return num_anomalies