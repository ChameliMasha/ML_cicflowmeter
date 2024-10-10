import pandas as pd

# Load the uploaded CSV file
file_path = '/Users/M S I/Desktop/check/benign-dec.pcap_Flow.csv'
# file_path = 'benign-dec.pcap_Flow.csv'
df = pd.read_csv(file_path)

# Define the new column names
new_column_names = [
    "Flow_ID", "Src_IP", "Src_Port", "Dst_IP", "Dst_Port", "Protocol", "Timestamp",
    "Flow_Duration", "Tot_Fwd_Pkts", "Tot_Bwd_Pkts", "TotLen_Fwd_Pkts", "TotLen_Bwd_Pkts", 
    "Fwd_Pkt_Len_Max", "Fwd_Pkt_Len_Min", "Fwd_Pkt_Len_Mean", "Fwd_Pkt_Len_Std", 
    "Bwd_Pkt_Len_Max", "Bwd_Pkt_Len_Min", "Bwd_Pkt_Len_Mean", "Bwd_Pkt_Len_Std", 
    "Flow_Byts/s", "Flow_Pkts/s", "Flow_IAT_Mean", "Flow_IAT_Std", "Flow_IAT_Max", 
    "Flow_IAT_Min", "Fwd_IAT_Tot", "Fwd_IAT_Mean", "Fwd_IAT_Std", "Fwd_IAT_Max", 
    "Fwd_IAT_Min", "Bwd_IAT_Tot", "Bwd_IAT_Mean", "Bwd_IAT_Std", "Bwd_IAT_Max", 
    "Bwd_IAT_Min", "Fwd_PSH_Flags", "Bwd_PSH_Flags", "Fwd_URG_Flags", "Bwd_URG_Flags", 
    "Fwd_Header_Len", "Bwd_Header_Len", "Fwd_Pkts/s", "Bwd_Pkts/s", "Pkt_Len_Min", 
    "Pkt_Len_Max", "Pkt_Len_Mean", "Pkt_Len_Std", "Pkt_Len_Var", "FIN_Flag_Cnt", 
    "SYN_Flag_Cnt", "RST_Flag_Cnt", "PSH_Flag_Cnt", "ACK_Flag_Cnt", "URG_Flag_Cnt", 
    "CWE_Flag_Count", "ECE_Flag_Cnt", "Down/Up_Ratio", "Pkt_Size_Avg", "Fwd_Seg_Size_Avg", 
    "Bwd_Seg_Size_Avg", "Fwd_Byts/b_Avg", "Fwd_Pkts/b_Avg", "Fwd_Blk_Rate_Avg", 
    "Bwd_Byts/b_Avg", "Bwd_Pkts/b_Avg", "Bwd_Blk_Rate_Avg", "Subflow_Fwd_Pkts", 
    "Subflow_Fwd_Byts", "Subflow_Bwd_Pkts", "Subflow_Bwd_Byts", "Init_Fwd_Win_Byts", 
    "Init_Bwd_Win_Byts", "Fwd_Act_Data_Pkts", "Fwd_Seg_Size_Min", "Active_Mean", 
    "Active_Std", "Active_Max", "Active_Min", "Idle_Mean", "Idle_Std", "Idle_Max", 
    "Idle_Min", "Label"
]

# Update the DataFrame's column names
df.columns = new_column_names

# Save the updated DataFrame to a new CSV file
output_file_path = '/Users/M S I/Desktop/check/updated_benign_flow.csv'
df.to_csv(output_file_path, index=False)

output_file_path


