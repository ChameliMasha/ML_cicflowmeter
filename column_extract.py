import pandas as pd


columns_to_keep = ['src_ip','src_port','dst_ip','dst_port','protocol','flow_duration','tot_fwd_pkts','tot_bwd_pkts','totlen_fwd_pkts', 'totlen_bwd_pkts','flow_byts_s','flow_pkts_s', 'fwd_iat_std','bwd_iat_std','fwd_pkts_s','bwd_pkts_s','pkt_len_min','pkt_len_max','pkt_len_std','fin_flag_cnt','syn_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt','ack_flag_cnt','urg_flag_cnt','cwr_flag_count','down_up_ratio']

def filter_columns(input_file):

    output_file = './filtered_output_csv/output2Filtered.csv'
    # Load the CSV file
    data = pd.read_csv(input_file)
    
    # Select the required columns
    filtered_data = data[columns_to_keep]
    
    # Save the filtered DataFrame to a new CSV file
    filtered_data.to_csv(output_file, index=False)
    




# Call the function to filter columns and save the result
# filter_columns(input_file, output_file, columns_to_keep)

# # Specify the columns to keep
# columns_to_keep = [
#     'Src_IP',
#  'Src_Port',
#  'Dst_IP',
#  'Dst_Port',
#  'Protocol',
#  'Flow_Duration',
#  'Tot_Fwd_Pkts',
#  'Tot_Bwd_Pkts',
#  'TotLen_Fwd_Pkts',
#  'TotLen_Bwd_Pkts',
#  'Flow_Byts/s',
#  'Flow_Pkts/s',
#  'Fwd_IAT_Std',
#  'Bwd_IAT_Std',
#  'Fwd_Pkts/s',
#  'Bwd_Pkts/s',
#  'Pkt_Len_Min',
#  'Pkt_Len_Max',
#  'Pkt_Len_Std',
#  'FIN_Flag_Cnt',
#  'SYN_Flag_Cnt',
#  'RST_Flag_Cnt',
#  'PSH_Flag_Cnt',
#  'ACK_Flag_Cnt',
#  'URG_Flag_Cnt',
#  'CWE_Flag_Count',
#  'Down/Up_Ratio',
#  # 'Label'

# ]





