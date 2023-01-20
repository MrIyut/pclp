#!/usr/bin/python3

MAX_F_IAT = 90000
CRYPTOMINER_RESPONSE_PORTS = [137, 138, 1947]

def is_long_flow_duration(flow_duration: str):
	if flow_duration[7] > '0':
		return 1
	if flow_duration[7] == '0' and len(flow_duration[7]) > 8 and flow_duration[8] == '.': # >=0.97 sec
		if flow_duration[9] == '9' and flow_duration[10] >= '7':
			return 1
	return 0

def analyze_traffic(traffic: str):
    decoded = traffic.split(",")
    flow_duration = decoded[4].split(" ")
    flow_dur = float(flow_duration[2][7:])
    long_flow_duration = is_long_flow_duration(flow_duration[2])
    avg_pay0 = (0, 1) [decoded[-1] == "0.0"]
    approx_zero_duration = (0, 1) [flow_dur < 0.001]
    fwd_header_size_tot = int(decoded[8])
    high_fwd_header_size = (0, 1) [fwd_header_size_tot > 1000]
    fwd_iat_avg = float(decoded[14])
    origin_ip = decoded[0].split(".")
    response_ip = decoded[2].split(".")
    flow_ACK_flag_count = int(decoded[11])
    same_network = 1

    for i in range(0, 1):
        if origin_ip[i] != response_ip[i]:
            same_network = 0
            break
    
    response_port = int(decoded[3])
    miner_port = (0, 1)[response_port in CRYPTOMINER_RESPONSE_PORTS]
    
    if approx_zero_duration and same_network and miner_port:
        if not avg_pay0:
            return 1 #cryptominer
    else: 
        if not avg_pay0 and flow_dur != 0 and fwd_iat_avg != 0:
            value = fwd_iat_avg / flow_dur
            if value > MAX_F_IAT and same_network and miner_port:
                return 1 #cryptominer
    
    high_traffic = (0, 1) [long_flow_duration or flow_ACK_flag_count >= 75]
    if high_traffic and not avg_pay0 and high_fwd_header_size:
        return 1 #bruteforce
        
    return 0


def check_traffic():
    traffic = open("./data/traffic/traffic.in", "r").readlines()
    output_task2 = open("traffic-predictions.out", "w")

    for i in range(len(traffic)):
        if i == 0:
            continue

        if traffic[i][-1] == '\n':
            traffic[i] = traffic[i][:-1]
        verdict = analyze_traffic(traffic[i])
        output_task2.write(str(verdict) + "\n")

    output_task2.close()    