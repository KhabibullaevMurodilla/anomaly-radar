"""
Generates a synthetic Modbus/TCP pcap to validate the parser + feature
pipeline end-to-end, since we don't have a licensed real OT capture yet
(see TODO.md for the dataset vetting step).

Models a simple, realistic pattern:
  - One HMI/SCADA master (10.0.0.10) polling three PLCs (10.0.0.21-23)
  - Normal behaviour: periodic read_holding_registers polls (every ~2s)
    plus occasional legitimate write_single_register commands
    (e.g. a setpoint change), with values inside a known-safe range.
  - Injected anomalies (label kept in a sidecar CSV, not in the pcap
    itself — the model should find these from protocol behaviour alone):
      1. Unusual function code never seen in the normal baseline (0x17)
      2. A write to a register no legitimate controller writes to
      3. A write value far outside the normal operating range
      4. A burst of requests far faster than the normal poll cadence
         (reconnaissance-like scanning behaviour)
"""

from __future__ import annotations

import csv
import random

from scapy.all import wrpcap
from scapy.contrib.modbus import (
    ModbusADURequest,
    ModbusADUResponse,
    ModbusPDU03ReadHoldingRegistersRequest,
    ModbusPDU03ReadHoldingRegistersResponse,
    ModbusPDU06WriteSingleRegisterRequest,
    ModbusPDU06WriteSingleRegisterResponse,
    ModbusPDU17ReadWriteMultipleRegistersRequest,
    ModbusPDU17ReadWriteMultipleRegistersResponse,
)
from scapy.layers.inet import IP, TCP, Ether

random.seed(42)

MASTER_IP = "10.0.0.10"
PLC_IPS = ["10.0.0.21", "10.0.0.22", "10.0.0.23"]
MODBUS_PORT = 502

NORMAL_HOLDING_REGISTER_RANGE = (100, 400, 0, 4000)  # addr_start, addr_end, val_min, val_max

packets = []
labels = []  # sidecar ground truth: (transaction_id, src, dst, is_anomaly, anomaly_type)

t = 1_700_000_000.0  # arbitrary unix epoch start
trans_id = 1


def make_pair(src, dst, unit_id, req_pdu, resp_pdu, ts, anomaly=None):
    global trans_id
    tid = trans_id
    trans_id += 1

    req = (
        Ether() / IP(src=src, dst=dst) / TCP(sport=50000 + tid % 1000, dport=MODBUS_PORT)
        / ModbusADURequest(transId=tid, unitId=unit_id) / req_pdu
    )
    req.time = ts

    resp = (
        Ether() / IP(src=dst, dst=src) / TCP(sport=MODBUS_PORT, dport=50000 + tid % 1000)
        / ModbusADUResponse(transId=tid, unitId=unit_id) / resp_pdu
    )
    resp.time = ts + random.uniform(0.002, 0.02)

    packets.append(req)
    packets.append(resp)
    labels.append({"transaction_id": tid, "src": src, "dst": dst, "is_anomaly": anomaly is not None,
                    "anomaly_type": anomaly or ""})


# --- Normal baseline traffic: ~500 polling cycles across 3 PLCs ---
for cycle in range(500):
    for plc in PLC_IPS:
        addr = random.randint(*NORMAL_HOLDING_REGISTER_RANGE[:2])
        qty = random.choice([1, 2, 4])
        make_pair(
            MASTER_IP, plc, unit_id=1,
            req_pdu=ModbusPDU03ReadHoldingRegistersRequest(startAddr=addr, quantity=qty),
            resp_pdu=ModbusPDU03ReadHoldingRegistersResponse(
                byteCount=qty * 2, registerVal=[random.randint(0, 4000) for _ in range(qty)]),
            ts=t,
        )
        t += 2.0 + random.uniform(-0.1, 0.1)

        # occasional legitimate setpoint write, inside normal range
        if random.random() < 0.02:
            addr = random.randint(*NORMAL_HOLDING_REGISTER_RANGE[:2])
            val = random.randint(*NORMAL_HOLDING_REGISTER_RANGE[2:])
            make_pair(
                MASTER_IP, plc, unit_id=1,
                req_pdu=ModbusPDU06WriteSingleRegisterRequest(registerAddr=addr, registerValue=val),
                resp_pdu=ModbusPDU06WriteSingleRegisterResponse(registerAddr=addr, registerValue=val),
                ts=t,
            )
            t += 0.05

# --- Anomaly 1: unusual function code (0x17 read/write multiple) ---
make_pair(
    MASTER_IP, PLC_IPS[0], unit_id=1,
    req_pdu=ModbusPDU17ReadWriteMultipleRegistersRequest(
        readStartingAddr=100, readQuantityRegisters=2,
        writeStartingAddr=900, writeQuantityRegisters=1, writeRegistersValue=[9999]),
    resp_pdu=ModbusPDU17ReadWriteMultipleRegistersResponse(byteCount=4, registerVal=[0, 0]),
    ts=t, anomaly="unusual_function_code",
)
t += 2.0

# --- Anomaly 2: write to a register no legitimate controller writes to ---
make_pair(
    MASTER_IP, PLC_IPS[1], unit_id=1,
    req_pdu=ModbusPDU06WriteSingleRegisterRequest(registerAddr=9001, registerValue=1),
    resp_pdu=ModbusPDU06WriteSingleRegisterResponse(registerAddr=9001, registerValue=1),
    ts=t, anomaly="write_to_unusual_register",
)
t += 2.0

# --- Anomaly 3: write value far outside normal operating range ---
make_pair(
    MASTER_IP, PLC_IPS[2], unit_id=1,
    req_pdu=ModbusPDU06WriteSingleRegisterRequest(registerAddr=200, registerValue=65000),
    resp_pdu=ModbusPDU06WriteSingleRegisterResponse(registerAddr=200, registerValue=65000),
    ts=t, anomaly="out_of_range_write_value",
)
t += 2.0

# --- Anomaly 4: burst of rapid-fire reads (scan-like behaviour) ---
for i in range(40):
    make_pair(
        MASTER_IP, PLC_IPS[0], unit_id=1,
        req_pdu=ModbusPDU03ReadHoldingRegistersRequest(startAddr=i, quantity=1),
        resp_pdu=ModbusPDU03ReadHoldingRegistersResponse(byteCount=2, registerVal=[0]),
        ts=t, anomaly="rapid_scan_burst",
    )
    t += 0.01  # 10ms apart vs normal ~2s cadence

packets.sort(key=lambda p: p.time)
wrpcap("data/synthetic/modbus_traffic.pcap", packets)

with open("data/synthetic/ground_truth_labels.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["transaction_id", "src", "dst", "is_anomaly", "anomaly_type"])
    writer.writeheader()
    writer.writerows(labels)

print(f"Wrote {len(packets)} packets ({len(labels)} transactions) to data/synthetic/modbus_traffic.pcap")
print(f"Ground truth: {sum(l['is_anomaly'] for l in labels)} anomalous transactions out of {len(labels)}")
