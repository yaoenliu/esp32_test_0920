import subprocess
import os
import sys
import random

# Get the directory where this script is located
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def run_script(script_name):
    """Execute the specified Python script"""
    print(f"\n{'='*60}")
    print(f"Running script: {script_name}")
    print('='*60)
    
    # Build absolute path to the script
    script_path = os.path.join(SCRIPT_DIR, script_name)
    
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='replace',
            check=True,
            cwd=SCRIPT_DIR  # Execute in the script's directory
        )
        print(result.stdout)
        if result.stderr:
            print(f"Warning: {result.stderr}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to execute {script_name}")
        print(f"Error message: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"Error: Script {script_name} not found")
        return False

def merge_jsonl_files(output_file="test_data.jsonl"):
    """Merge all .jsonl test data files and randomly shuffle content"""
    print(f"\n{'='*60}")
    print("Starting to merge test data...")
    print('='*60)
    
    # List of files to merge
    jsonl_files = [
        "echo_test_data.jsonl",
        "db_query_test_data.jsonl",
        "run_cmd_test_data.jsonl",
        "temp_cmd_test_data.jsonl",
        "mix_test_data.jsonl",
        "pure_garbage.jsonl"
    ]
    
    all_lines = []
    
    # Use absolute paths for all files
    output_file = os.path.join(SCRIPT_DIR, output_file)
    
    try:
        # First read all lines into memory
        for jsonl_file in jsonl_files:
            file_path = os.path.join(SCRIPT_DIR, jsonl_file)
            if os.path.exists(file_path):
                print(f"Reading: {jsonl_file}")
                with open(file_path, 'r', encoding='utf-8') as infile:
                    lines = infile.readlines()
                    all_lines.extend(lines)
                    print(f"  ✓ Added {len(lines)} lines")
            else:
                print(f"  ✗ Warning: {jsonl_file} does not exist, skipping")
        
        # Randomly shuffle all lines
        print(f"\nRandomly shuffling {len(all_lines)} lines...")
        random.shuffle(all_lines)
        
        # Write to output file
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.writelines(all_lines)
        
        print(f"\n{'='*60}")
        print(f"Merge complete!")
        print(f"Output file: {output_file}")
        print(f"Total lines: {len(all_lines)}")
        print(f"All lines randomly shuffled")
        print('='*60)
        return True
        
    except Exception as e:
        print(f"Error: Failed to merge files")
        print(f"Error message: {str(e)}")
        return False

def cleanup_generated_files():
    """Delete generated intermediate test data files (keep merged file)"""
    print(f"\n{'='*60}")
    print("Cleaning up intermediate files...")
    print('='*60)
    
    files_to_delete = [
        "echo_test_data.jsonl",
        "db_query_test_data.jsonl",
        "run_cmd_test_data.jsonl",
        "temp_cmd_test_data.jsonl",
        "mix_test_data.jsonl",
        "pure_garbage.jsonl"
        # Note: Do not delete merged_test_data.jsonl
    ]
    
    deleted_count = 0
    for file in files_to_delete:
        file_path = os.path.join(SCRIPT_DIR, file)
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"  ✓ Deleted: {file}")
                deleted_count += 1
            except Exception as e:
                print(f"  ✗ Cannot delete {file}: {str(e)}")
        else:
            print(f"  - File does not exist: {file}")
    
    print(f"\n{'='*60}")
    print(f"Cleanup complete! Deleted {deleted_count} intermediate files")
    print(f"Kept final result: merged_test_data.jsonl")
    print('='*60)

def main():
    """Main program"""
    print("=" * 60)
    print("Test Data Generation and Merge Tool")
    print("=" * 60)
    
    # List of scripts to execute
    scripts = [
        "echo.py",
        "db_query.py",
        "run_cmd.py",
        "temp_report.py",
        "mix.py",
        "pure_garbage.py"
    ]
    
    # Execute all scripts
    success_count = 0
    for script in scripts:
        if run_script(script):
            success_count += 1
    
    print(f"\n{'='*60}")
    print(f"Script execution result: {success_count}/{len(scripts)} succeeded")
    print('='*60)
    
    # If all scripts executed successfully, merge files
    if success_count == len(scripts):
        merge_jsonl_files()
    else:
        print("\nWarning: Some scripts failed, still attempting to merge existing files...")
        merge_jsonl_files()
    
    # Clean up all generated files
    cleanup_generated_files()
    
    print("\nAll tasks completed!")

if __name__ == "__main__":
    main()
