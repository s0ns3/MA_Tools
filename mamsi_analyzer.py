'''
#########################################################
The script below will extract suspicious scripts from msi
#######################MHG###############################
'''

# The script will search for 'current.msi', you can change it right below:
file_name = "current.msi"

script_ptr = [b'\x43\x75\x73\x74\x6F\x6D\x41\x63\x74\x69\x6F\x6E\x44\x61\x74\x61\x44\x69\x67\x69\x74\x61\x6C\x6C\x79\x53\x69\x67\x6E\x53\x63\x72\x69\x70\x74',
              b'\x53\x45\x54\x55\x50\x45\x58\x45\x50\x41\x54\x48']

print("[+] Scanning MSI: " + file_name)

with open(file_name, 'rb') as msi_file:

    msi_valid = msi_file.read(8)

    if b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' in msi_valid or b'\x23\x20' in msi_valid:

        print("[+] Valid MSI")
        msi_data = msi_file.read(1024)
        print("[*] Reading file...")
        output_index = 1

        while len(msi_data) != 0:
            try:
                if len(list(filter(lambda ptr: ptr in msi_data, script_ptr))) > 0:
                    print("[+] Found it! Presented decoded bytes:")
                    print(msi_data.decode("ascii"))
                    print("[+] Extracting Script...")
                    script_data = msi_data.decode('utf-8')

                    while b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00' not in msi_data:
                        msi_data = msi_file.read(300)
                        try:
                            script_data += msi_data.decode("utf-8")
                        except Exception as err:
                            print("[+] Exit with decoding error: " + str(err))
                            break

                    with open("output_script" + str(output_index) + ".txt", "w") as script_file:
                        script_file.write(script_data)
                        print("[+] Script extracted")
                        output_index += 1

            except Exception as err:
                print("[!] Exception while executing operation: " + str(err))
                print("[*] Continue reading...")
                msi_data = msi_file.read(1024)

            else:
                msi_data = msi_file.read(1024)

    else:
        print("Invalid MSI")
