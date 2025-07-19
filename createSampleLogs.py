#!/usr/bin/env python3
"""
Demo script showing MongoDB log redaction in action
"""


def demo_redaction():
    """Demonstrate the redaction tool with sample data"""

    # Sample on-premises log entry
    onprem_sample = '''2025-07-15T11:49:10.372+0000 I  COMMAND  [conn297396] command default.coway_outbound_survey command: aggregate { aggregate: "coway_outbound_survey", pipeline: [ { $match: { $and: [ { phone_number: "60124471286" }, { createdAt: { $gt: 1751975350218.0 } }, { sent: { $exists: true } }, { delivered: { $exists: false } } ] } } ], allowDiskUse: true, cursor: {}, lsid: { id: UUID("18dc6629-9262-4055-b3fa-6c00285da25b") }, $db: "default" }'''

    # Sample Atlas log entry
    atlas_sample = '''{"t":{"$date":"2025-07-16T05:18:53.846+00:00"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn15191","msg":"Connection ended","attr":{"remote":"192.168.248.116:45292","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"d2b52b4f-2a9d-4033-ab45-b3b4de28de12"}},"connectionId":15191,"connectionCount":84}}'''

    print("=== MONGODB LOG REDACTION DEMO ===\n")

    # Import the redactor (assuming the main script is imported)
    try:
        from mongo_log_redactor import MongoLogRedactor
    except ImportError:
        print("Note: This demo requires the MongoLogRedactor class")
        print("Run this alongside the main logRedactor.py file")
        return

    redactor = MongoLogRedactor()

    print("1. ORIGINAL ON-PREMISES LOG:")
    print("-" * 50)
    print(onprem_sample[:200] + "...")
    print()

    print("2. REDACTED ON-PREMISES LOG:")
    print("-" * 50)
    redacted_onprem = redactor.redact_onprem_log(onprem_sample)
    print(redacted_onprem[:200] + "...")
    print()

    # Reset for Atlas demo
    redactor = MongoLogRedactor()

    print("3. ORIGINAL ATLAS LOG:")
    print("-" * 50)
    print(atlas_sample)
    print()

    print("4. REDACTED ATLAS LOG:")
    print("-" * 50)
    redacted_atlas = redactor.redact_atlas_log(atlas_sample)
    print(redacted_atlas)
    print()

    print("5. REDACTION MAPPING EXAMPLE:")
    print("-" * 50)
    for category, mappings in redactor.redaction_mapping.items():
        if mappings:
            print(f"{category.upper()}:")
            for original, redacted in mappings.items():
                print(f"  {original} → {redacted}")
    print()


def create_sample_files():
    """Create sample log files for testing"""

    onprem_sample = '''2025-07-15T11:49:10.372+0000 I  COMMAND  [conn297396] command default.coway_outbound_survey command: aggregate { aggregate: "coway_outbound_survey", pipeline: [ { $match: { $and: [ { phone_number: "60124471286" }, { createdAt: { $gt: 1751975350218.0 } }, { sent: { $exists: true } }, { delivered: { $exists: false } } ] } } ], allowDiskUse: true, cursor: {}, lsid: { id: UUID("18dc6629-9262-4055-b3fa-6c00285da25b") }, $db: "default" } planSummary: IXSCAN { phone_number: 1 } keysExamined:15 docsExamined:15 cursorExhausted:1 numYields:9 nreturned:1 queryHash:D2F77013 planCacheKey:65F9BBFA reslen:4118 locks:{ ReplicationStateTransition: { acquireCount: { w: 10 } }, Global: { acquireCount: { r: 10 } }, Database: { acquireCount: { r: 10 } }, Collection: { acquireCount: { r: 10 } }, Mutex: { acquireCount: { r: 1 } } } storage:{ data: { bytesRead: 1618737, timeReadingMicros: 151257 } } protocol:op_msg 151ms
2025-07-15T11:49:10.373+0000 I  COMMAND  [conn297382] command default.coway_outbound_survey command: aggregate { aggregate: "coway_outbound_survey", pipeline: [ { $match: { $and: [ { phone_number: "60142068482" }, { createdAt: { $gt: 1751975350268.0 } }, { sent: { $exists: true } }, { delivered: { $exists: false } } ] } } ], allowDiskUse: true, cursor: {}, lsid: { id: UUID("0fdad84c-db14-4540-8bf9-cf602fdaf576") }, $db: "default" } planSummary: IXSCAN { phone_number: 1 } keysExamined:14 docsExamined:14 cursorExhausted:1 numYields:6 nreturned:1 queryHash:D2F77013 planCacheKey:65F9BBFA reslen:4112 locks:{ ReplicationStateTransition: { acquireCount: { w: 7 } }, Global: { acquireCount: { r: 7 } }, Database: { acquireCount: { r: 7 } }, Collection: { acquireCount: { r: 7 } }, Mutex: { acquireCount: { r: 1 } } } storage:{ data: { bytesRead: 1296427, timeReadingMicros: 102813 } } protocol:op_msg 103ms
2025-07-15T11:49:10.468+0000 I  NETWORK  [conn297484] end connection 10.201.32.211:38282 (138 connections now open)'''

    atlas_sample = '''{"t":{"$date":"2025-07-16T05:18:53.846+00:00"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn15191","msg":"Connection ended","attr":{"remote":"192.168.248.116:45292","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"d2b52b4f-2a9d-4033-ab45-b3b4de28de12"}},"connectionId":15191,"connectionCount":84}}
{"t":{"$date":"2025-07-16T05:18:53.846+00:00"},"s":"I","c":"NETWORK","id":22944,"ctx":"conn15192","msg":"Connection ended","attr":{"remote":"192.168.248.116:45314","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"0be2ba28-d4ef-4565-9dbb-73d100f1576c"}},"connectionId":15192,"connectionCount":83}}
{"t":{"$date":"2025-07-16T05:19:38.920+00:00"},"s":"I","c":"NETWORK","id":22943,"ctx":"listener","msg":"Connection accepted","attr":{"remote":"192.168.248.116:52366","isLoadBalanced":false,"uuid":{"uuid":{"$uuid":"ac7e5a08-53b5-4b6f-87bf-8d9d1f99b7a2"}},"connectionId":15193,"connectionCount":83}}'''

    # Write sample files
    with open('logs/sample_onprem.log', 'w') as f:
        f.write(onprem_sample)

    with open('logs/sample_atlas.log', 'w') as f:
        f.write(atlas_sample)

    print("Sample files created:")
    print("  - sample_onprem.log (On-premises format)")
    print("  - sample_atlas.log (Atlas format)")
    print("\nTo test the redactor:")
    print("  python logRedactor.py sample_onprem.log")
    print("  python logRedactor.py sample_atlas.log")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1 and sys.argv[1] == "create-samples":
        create_sample_files()
    else:
        demo_redaction()