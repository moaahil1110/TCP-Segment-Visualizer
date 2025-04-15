import pyshark
import pandas as pd
import matplotlib.pyplot as plt
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

############################################
# Helper function for safe flag extraction
############################################
def safe_flag_extraction(flag):
    try:
        return '1' if int(flag) == 1 else '0'
    except (ValueError, AttributeError):
        return '1' if str(flag).lower() == 'true' else '0'

############################################
# Data Extraction
############################################


def extract_tcp_data(file_path):
    rtt_logs = []  

    # First capture for raw RTT logs
    cap = pyshark.FileCapture(file_path, display_filter='tcp.analysis.ack_rtt')
    for pkt in cap:
        try:
            rtt = float(pkt.tcp.analysis_ack_rtt)  # Extract RTT value
            rtt_logs.append(f"ACK RTT: {rtt:.9f}")
        except (AttributeError, ValueError):
            rtt_logs.append("No RTT info in this packet.")
    cap.close()

    # Restart capture for full data extraction (using all packets)
    cap = pyshark.FileCapture(file_path)
    data = []
    for packet in cap:
        try:
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport
            seq = int(packet.tcp.seq)
            ack = int(packet.tcp.ack)
            timestamp = float(packet.sniff_time.timestamp())
            rwnd = int(packet.tcp.window_size_value)
            
            # Use the robust flag extraction function
            syn_flag = safe_flag_extraction(packet.tcp.flags_syn)
            ack_flag = safe_flag_extraction(packet.tcp.flags_ack)
            fin_flag = safe_flag_extraction(packet.tcp.flags_fin)
            
            # Create flags field for easier processing
            flags = ''
            if syn_flag == '1':
                flags += 'syn '
            if ack_flag == '1':
                flags += 'ack '
            if fin_flag == '1':
                flags += 'fin '
            flags = flags.strip()
            
            
            try:
                tcp_len = int(packet.tcp.len)
            except (AttributeError, ValueError):
                try:
                    tcp_len = int(packet.tcp.calculated_length)
                except (AttributeError, ValueError):
                    try:
                        ip_len = int(packet.ip.len)
                        ip_hdr = int(packet.ip.hdr_len)
                        tcp_hdr = int(packet.tcp.hdr_len)
                        tcp_len = ip_len - ip_hdr - tcp_hdr
                        if tcp_len < 0:
                            tcp_len = 0
                    except (AttributeError, ValueError):
                        tcp_len = 0
            
            data.append((src_ip, dst_ip, src_port, dst_port, seq, ack, timestamp, rwnd, 
                         syn_flag, ack_flag, fin_flag, flags, tcp_len))
        except AttributeError:
            continue  
    
    cap.close()
    df = pd.DataFrame(data, columns=['Source', 'Destination', 'Src Port', 'Dst Port', 
                                       'Seq', 'Ack', 'Timestamp', 'RWND', 'SYN', 'ACK', 
                                       'FIN', 'Flags', 'Len'])
    return df, rtt_logs

############################################
# RTT Calculations
############################################

def add_handshake_rtt(df):
    df = df.sort_values(by='Timestamp').reset_index(drop=True)
    df['RTT'] = None
    syn_sent = {} 
    
    for i, row in df.iterrows():
        key = (row['Source'], row['Destination'], row['Src Port'], row['Dst Port'])
        rev_key = (row['Destination'], row['Source'], row['Dst Port'], row['Src Port'])
        
        if row['SYN'] == '1' and row['ACK'] == '0':
            syn_sent[key] = (row['Seq'], row['Timestamp'])
        elif row['SYN'] == '1' and row['ACK'] == '1':
            if rev_key in syn_sent:
                syn_seq, syn_time = syn_sent[rev_key]
                if row['Ack'] == syn_seq + 1:
                    df.at[i, 'RTT'] = row['Timestamp'] - syn_time
    return df

def calculate_rtt_all(df):
    df = df.sort_values(by='Timestamp').reset_index(drop=True)
    df['RTT_Data'] = None
    sent_packets = {} 
    flows = []
    for _, row in df.iterrows():
        flow_key_1 = (row['Source'], row['Destination'], row['Src Port'], row['Dst Port'])
        flow_key_2 = (row['Destination'], row['Source'], row['Dst Port'], row['Src Port'])
        if flow_key_1 not in flows and flow_key_2 not in flows:
            flows.append(flow_key_1)
    
    for i, row in df.iterrows():
        if row['Len'] > 0:
            key_sent = (row['Source'], row['Destination'], row['Src Port'], row['Dst Port'], row['Seq'])
            sent_packets[key_sent] = (row['Timestamp'], row['Len'])
        
        if row['ACK'] == '1':
            for flow_key in flows:
                src, dst, sport, dport = flow_key
                rev_flow = (dst, src, dport, sport)
                if (row['Source'] == rev_flow[0] and row['Destination'] == rev_flow[1] and
                    row['Src Port'] == rev_flow[2] and row['Dst Port'] == rev_flow[3]):
                    ack_value = row['Ack']
                    matched_keys = []
                    for sent_key, (sent_time, sent_len) in sent_packets.items():
                        sent_src, sent_dst, sent_sport, sent_dport, sent_seq = sent_key
                        if (sent_src == dst and sent_dst == src and 
                            sent_sport == dport and sent_dport == sport):
                            seq_end = sent_seq + sent_len
                            if ack_value >= seq_end:
                                curr_rtt = row['Timestamp'] - sent_time
                                if 0 < curr_rtt < 10:
                                    df.at[i, 'RTT_Data'] = curr_rtt
                                    matched_keys.append(sent_key)
                    for key in matched_keys:
                        sent_packets.pop(key, None)
    return df

############################################
# Timeout Calculation
############################################

def calculate_timeout_intervals(df):
    df_sorted = df.sort_values(by='Timestamp')
    timeout_data = []
    packet_history = {}
    
    for index, row in df_sorted.iterrows():
        if row['Len'] > 0:
            key = (row['Source'], row['Destination'], row['Seq'])
            if key in packet_history:
                prev_time = packet_history[key]
                interval = row['Timestamp'] - prev_time
                if interval > 0.2:
                    timeout_data.append((row['Timestamp'], interval))
                packet_history[key] = row['Timestamp']
            else:
                packet_history[key] = row['Timestamp']
    return timeout_data

############################################
# Plotting Functions
############################################

def plot_graph(notebook, values, title, xlabel, ylabel, color):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)
    fig = Figure(figsize=(8, 6))
    ax = fig.add_subplot(111)
    
    if isinstance(values[0], tuple):
        timestamps = [t[0] for t in values]
        intervals = [t[1] for t in values]
        ax.plot(timestamps, intervals, marker='o', linestyle='-', color=color)
        ax.set_xlabel("Time (s)")
    else:
        ax.plot(values, marker='o', linestyle='-', color=color)
        ax.set_xlabel(xlabel)
        
    ax.set_title(title)
    ax.set_ylabel(ylabel)
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    canvas.draw()

def plot_time_series(notebook, timestamps, values, title, ylabel, color):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text=title)
    fig = Figure(figsize=(8, 6))
    ax = fig.add_subplot(111)
    ax.plot(timestamps, values, marker='o', linestyle='-', color=color)
    ax.set_title(title)
    ax.set_xlabel("Time (s)")
    ax.set_ylabel(ylabel)
    canvas = FigureCanvasTkAgg(fig, master=frame)
    canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    canvas.draw()

def plot_rtt_graph(notebook, df):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="RTT Analysis")
    rtt_notebook = ttk.Notebook(frame)
    rtt_notebook.pack(fill=tk.BOTH, expand=True)
    
    # RTT Scatter Plot Tab
    scatter_frame = ttk.Frame(rtt_notebook)
    rtt_notebook.add(scatter_frame, text="RTT Scatter Plot")
    fig1 = Figure(figsize=(8, 6))
    ax1 = fig1.add_subplot(111)
    
    handshake_df = df[df['RTT'].notna()]
    if not handshake_df.empty:
        ax1.scatter(handshake_df['Timestamp'], handshake_df['RTT'], 
                    color='blue', label='Handshake RTT', marker='s')
    
    data_df = df[df['RTT_Data'].notna()]
    if not data_df.empty:
        ax1.scatter(data_df['Timestamp'], data_df['RTT_Data'], 
                    color='red', label='Data RTT', marker='o')
    
    ax1.set_title("Round Trip Time (RTT)")
    ax1.set_xlabel("Time (s)")
    ax1.set_ylabel("RTT (s)")
    ax1.legend()
    
    canvas1 = FigureCanvasTkAgg(fig1, master=scatter_frame)
    canvas1.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    canvas1.draw()
    
    # RTT Statistics Tab
    stats_frame = ttk.Frame(rtt_notebook)
    rtt_notebook.add(stats_frame, text="RTT Statistics")
    
    all_rtts = []
    if not handshake_df.empty:
        all_rtts.extend(handshake_df['RTT'].dropna().tolist())
    if not data_df.empty:
        all_rtts.extend(data_df['RTT_Data'].dropna().tolist())
    
    if all_rtts:
        stats_text = tk.Text(stats_frame, height=15, width=60)
        stats_text.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
        
        avg_rtt = sum(all_rtts) / len(all_rtts)
        min_rtt = min(all_rtts)
        max_rtt = max(all_rtts)
        variance = sum((x - avg_rtt) ** 2 for x in all_rtts) / len(all_rtts)
        std_dev = variance ** 0.5
        
        stats_text.insert(tk.END, f"Total RTT Samples: {len(all_rtts)}\n\n")
        stats_text.insert(tk.END, f"Average RTT: {avg_rtt:.6f} seconds\n")
        stats_text.insert(tk.END, f"Minimum RTT: {min_rtt:.6f} seconds\n")
        stats_text.insert(tk.END, f"Maximum RTT: {max_rtt:.6f} seconds\n")
        stats_text.insert(tk.END, f"RTT Standard Deviation: {std_dev:.6f} seconds\n\n")
        
        estimated_rto = avg_rtt + 4 * std_dev
        stats_text.insert(tk.END, f"Estimated RTO: {estimated_rto:.6f} seconds\n")
        stats_text.insert(tk.END, "(based on SRTT + 4*RTTVAR formula)\n\n")
        stats_text.insert(tk.END, "Note: TCP typically uses a more complex algorithm for RTO\n")
        stats_text.insert(tk.END, "calculation that involves weighted averages and exponential backoff.")
        stats_text.config(state=tk.DISABLED)
    else:
        no_data_label = tk.Label(stats_frame, text="No RTT data available", font=("Arial", 12))
        no_data_label.pack(pady=50)
    
    # RTT Histogram Tab (if enough data exists)
    if len(all_rtts) > 3:
        hist_frame = ttk.Frame(rtt_notebook)
        rtt_notebook.add(hist_frame, text="RTT Histogram")
        fig2 = Figure(figsize=(8, 6))
        ax2 = fig2.add_subplot(111)
        ax2.hist(all_rtts, bins='auto', color='green', alpha=0.7)
        ax2.set_title("RTT Distribution")
        ax2.set_xlabel("RTT (s)")
        ax2.set_ylabel("Frequency")
        canvas2 = FigureCanvasTkAgg(fig2, master=hist_frame)
        canvas2.get_tk_widget().pack(fill=tk.BOTH, expand=True)
        canvas2.draw()

############################################
# New Function: Display Raw RTT Log
############################################
def display_rtt_log(notebook, rtt_logs):
    """
    Create a new tab to display raw RTT log messages.
    """
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="RTT Log")
    
    text_widget = tk.Text(frame, wrap="none")
    text_widget.pack(fill=tk.BOTH, expand=True)
    
    scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.configure(yscrollcommand=scrollbar_y.set)
    
    for log in rtt_logs:
        text_widget.insert(tk.END, log + "\n")
    
    text_widget.config(state=tk.DISABLED)

############################################
# New Function: Display Calculated RTT Log
############################################
def display_calculated_rtt_log(notebook, df):
    """
    Create a new tab that displays a log of only those packets
    where an RTT (handshake or data) was calculated, showing Source and Destination IPs.
    """
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="Calculated RTT Log")
    
    text_widget = tk.Text(frame, wrap="none")
    text_widget.pack(fill=tk.BOTH, expand=True)
    
    scrollbar_y = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
    scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
    text_widget.configure(yscrollcommand=scrollbar_y.set)
    
    
    for idx, row in df.iterrows():
        if row['RTT'] is not None or row['RTT_Data'] is not None:
            log_line = f"Source: {row['Source']} -> Destination: {row['Destination']}: Time: {row['Timestamp']:.6f} s, "
            if row['RTT'] is not None:
                log_line += f"Handshake RTT: {row['RTT']:.9f} s, "
            if row['RTT_Data'] is not None:
                log_line += f"Data RTT: {row['RTT_Data']:.9f} s"
            text_widget.insert(tk.END, log_line.rstrip(", ") + "\n")
    
    text_widget.config(state=tk.DISABLED)

############################################
# GUI - TCP Headers Table
############################################

def show_tcp_headers_tab(notebook, df):
    frame = ttk.Frame(notebook)
    notebook.add(frame, text="TCP Headers")
    
    tree_frame = ttk.Frame(frame)
    tree_frame.pack(fill=tk.BOTH, expand=True)
    
    tree_scroll_y = ttk.Scrollbar(tree_frame)
    tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
    
    tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
    tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
    
    display_columns = ['Source', 'Destination', 'Src Port', 'Dst Port', 'Seq', 'Ack', 
                       'Timestamp', 'Flags', 'Len', 'RTT', 'RTT_Data']
    
    tree = ttk.Treeview(tree_frame, columns=display_columns, show='headings',
                        yscrollcommand=tree_scroll_y.set,
                        xscrollcommand=tree_scroll_x.set)
    
    tree_scroll_y.config(command=tree.yview)
    tree_scroll_x.config(command=tree.xview)
    
    for col in display_columns:
        tree.heading(col, text=col)
        max_width = max(len(str(df[col].max())), len(col)) * 10
        tree.column(col, width=min(max_width, 150))
    
    for _, row in df.iterrows():
        values = [row[col] for col in display_columns]
        tree.insert('', tk.END, values=values)
    
    tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

############################################
# Processing and GUI Assembly
############################################

def process_file(file_path):
    try:
        df, rtt_logs = extract_tcp_data(file_path)
        if df.empty:
            messagebox.showerror("Error", "No TCP packets found in the capture file.")
            return None
        
        df = add_handshake_rtt(df)
        df = calculate_rtt_all(df)
        
        result_window = tk.Toplevel()
        result_window.title(f"TCP Analysis - {file_path.split('/')[-1]}")
        result_window.geometry("900x700")
        
        notebook = ttk.Notebook(result_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        show_tcp_headers_tab(notebook, df)
        plot_rtt_graph(notebook, df)
        
        rwnd_data = df[['Timestamp', 'RWND']].dropna()
        if not rwnd_data.empty:
            plot_time_series(notebook, rwnd_data['Timestamp'], rwnd_data['RWND'], 
                             "Receive Window Size", "RWND (bytes)", "green")
        
        timeout_data = calculate_timeout_intervals(df)
        if timeout_data:
            plot_graph(notebook, timeout_data, "Packet Retransmissions", 
                       "Time (s)", "Timeout Interval (s)", "orange")
            
            rto_frame = ttk.Frame(notebook)
            notebook.add(rto_frame, text="Timeout Analysis")
            intervals = [interval for _, interval in timeout_data]
            avg_rto = sum(intervals) / len(intervals) if intervals else 0
            min_rto = min(intervals) if intervals else 0
            max_rto = max(intervals) if intervals else 0
            stats_text = tk.Text(rto_frame, height=10, width=50)
            stats_text.pack(padx=20, pady=20, fill=tk.BOTH, expand=True)
            stats_text.insert(tk.END, f"Total Retransmissions: {len(timeout_data)}\n\n")
            stats_text.insert(tk.END, f"Average Timeout Interval: {avg_rto:.3f} seconds\n")
            stats_text.insert(tk.END, f"Minimum Timeout Interval: {min_rto:.3f} seconds\n")
            stats_text.insert(tk.END, f"Maximum Timeout Interval: {max_rto:.3f} seconds\n\n")
            if len(intervals) > 1:
                sorted_intervals = sorted(intervals)
                backoff_evident = any(sorted_intervals[i+1] > sorted_intervals[i]*1.5 
                                       for i in range(len(sorted_intervals)-1))
                if backoff_evident:
                    stats_text.insert(tk.END, "Evidence of TCP exponential backoff detected.\n")
                    stats_text.insert(tk.END, "Timeout intervals increase after consecutive failures.")
                else:
                    stats_text.insert(tk.END, "No clear evidence of exponential backoff.\n")
            stats_text.config(state=tk.DISABLED)
        
       
        display_rtt_log(notebook, rtt_logs)
        
        
        display_calculated_rtt_log(notebook, df)
        
        return df
    
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")
        return None

############################################
# Main GUI for File Selection
############################################

def select_file():
    file_path = filedialog.askopenfilename(
        filetypes=[
            ("PCAP files", "*.pcap"),
            ("PCAPNG files", "*.pcapng"),
            ("All Files", "*.*")
        ]
    )
    if not file_path:
        return
    
    loading_label.config(text=f"Loading {file_path.split('/')[-1]}...")
    root.update()
    
    process_file(file_path)
    
    loading_label.config(text="Select a PCAP or PCAPNG file to analyze")

############################################
# Tkinter UI Setup
############################################

root = tk.Tk()
root.title("TCP Segment Analyzer")
root.geometry("500x250")

main_frame = ttk.Frame(root, padding=20)
main_frame.pack(fill=tk.BOTH, expand=True)

title_label = tk.Label(main_frame, text="TCP Segment Analyzer", font=("Arial", 16, "bold"))
title_label.pack(pady=(0, 20))

loading_label = tk.Label(main_frame, text="Select a PCAP or PCAPNG file to analyze", font=("Arial", 12))
loading_label.pack(pady=(0, 20))

button_frame = ttk.Frame(main_frame)
button_frame.pack(pady=10)

browse_button = ttk.Button(button_frame, text="Browse", command=select_file)
browse_button.pack(side=tk.LEFT, padx=5)

exit_button = ttk.Button(button_frame, text="Exit", command=root.destroy)
exit_button.pack(side=tk.LEFT, padx=5)

credits_label = tk.Label(main_frame, text="TCP Analysis Tool", font=("Arial", 8))
credits_label.pack(side=tk.BOTTOM, pady=10)

root.mainloop()