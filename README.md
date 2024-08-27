# Flow Log Parser

Python script parses flow log data from a file, and then maps each row to a tag based on a lookup table, and generates counts for each tag and port,  protocol combination.

## Requirements

- Python 3
- CSV module (built-in)
- argparse module (built-in)

## Usage

To run the Flow Log Parser script, use the following command:

```
python3 flow_log_parser.py <flow_log_file> <lookup_file> -t <tag_output_file> -p <port_output_file>
```

- `<flow_log_file>`: Path to the input file containing the flow log data.
- `<lookup_file>`: Path to the CSV file containing the lookup table for mapping ports and protocols to tags.
- `-t <tag_output_file>`: (Optional) Path to the output file for tag counts. Default is `tag_counts.csv`.
- `-p <port_output_file>`: (Optional) Path to the output file for port/protocol combination counts. Default is `port_protocol_counts.csv`.

## Input Files

1. Flow Log File:
   - The flow log file should be a plain text (ASCII) file.
   - Each line represents a flow record and should contain 14 space-separated fields.
   - The script expects the destination port to be the 6th field and the protocol number to be the 7th field.
   - The flow log file size can be up to 10 MB.

2. Lookup Table File:
   - The lookup table file should be a CSV file with 3 columns: `dstport`, `protocol`, and `tag`.
   - The `dstport` and `protocol` combination determines the tag to be applied.
   - The lookup file can have up to 10,000 mappings.
   - The tags can map to more than one port/protocol combination.
   - The matches are case-insensitive.

## Output Files

1. Tag Counts:
   - The script generates a CSV file with the count of matches for each tag.
   - The output file has two columns: `Tag` and `Count`.
   - If a matching tag is not found in the lookup table, the corresponding row is counted as 'Untagged'.

2. Port/Protocol Combination Counts:
   - The script generates a CSV file with the count of matches for each port/protocol combination.
   - The output file has three columns: `Port`, `Protocol`, and `Count`.

## Assumptions

- The protocol numbers in the flow log file can be mapped to protocol names using the hardcoded `PROTOCOL_TABLE` dictionary in the script.
- If a protocol number is not found in the `PROTOCOL_TABLE`, it is mapped to 'Unknown'.
- The script assumes that the flow log file and lookup table file are well-formatted and contain the expected columns.
- The script does not perform extensive error handling for invalid or missing data in the input files.

## Protocol Table

The script includes a hardcoded `PROTOCOL_TABLE` dictionary that maps protocol numbers to their corresponding names. 

If you need to update the protocol table, you can modify the `PROTOCOL_TABLE` dictionary in the script accordingly.
