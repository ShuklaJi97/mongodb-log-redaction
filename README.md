# 🚀 Quick Setup Guide

## 1. Download the Files

Ensure you have these files in your project directory:
```
mongodb-log-redactor/
├── logRedactor.py      # Main redaction tool
├── requirements.txt    # Dependencies
└── README.md          # Documentation
```

## 2. Install Dependencies

```bash
# Install required packages
pip install -r requirements.txt

# Or install directly
pip install phonenumbers>=8.12.0
```

## 3. Verify Installation

```bash
# Check if phonenumbers is installed
python -c "import phonenumbers; print('✅ Phone detection ready!')"
```

## 4. Test with Sample Data

Create a sample log file to test:

```bash
# Create test file
cat > sample_log.txt << 'EOF'
2025-07-15T11:49:10.372+0000 I COMMAND [conn297396] command default.survey 
command: aggregate { pipeline: [ { $match: { phone_number: "60124471286", 
contact: "+1-555-123-4567" } } ], lsid: { id: UUID("18dc6629-9262-4055-b3fa-6c00285da25b") } }
2025-07-15T11:49:10.468+0000 I NETWORK [conn297484] end connection 10.201.32.211:38282
EOF

# Run redaction
python logRedactor.py sample_log.txt

# Check output
cat sample_log.redacted.txt
```

## 5. Expected Output

You should see:
```
Processing ONPREM log format...

============================================================
REDACTION SUMMARY  
============================================================
Input File: sample_log.txt
Output File: sample_log.redacted.txt
Log Format: ONPREM

Redaction Statistics:
  phone_numbers: 2 items - International phone numbers in quotes
  ip_addresses: 1 items - IPv4 addresses
  uuids: 1 items - UUID identifiers
  legacy_conn_ids: 2 items - On-premises connection IDs

✅ Redaction completed successfully!
📁 Redacted log saved to: sample_log.redacted.txt
🌍 Enhanced with international phone number detection
```

## 6. Production Usage

```bash
# Basic usage
python logRedactor.py /var/log/mongodb/mongod.log

# With custom output
python logRedactor.py production.log clean_production.log

# Process Atlas logs
python logRedactor.py atlas_cluster.json atlas_clean.json
```

## 🎉 You're Ready!

The tool is now set up and ready to redact sensitive data from your MongoDB logs while preserving their structure and utility.

### Need Help?
- Check the full README.md for detailed documentation
- Ensure all files have proper permissions
- Verify Python 3.6+ is installed