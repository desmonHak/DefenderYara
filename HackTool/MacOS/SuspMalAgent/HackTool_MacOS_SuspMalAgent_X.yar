
rule HackTool_MacOS_SuspMalAgent_X{
	meta:
		description = "HackTool:MacOS/SuspMalAgent.X,SIGNATURE_TYPE_MACHOHSTR_EXT,35 00 35 00 0c 00 00 "
		
	strings :
		$a_00_0 = {6b 6c 69 73 74 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 20 7c 20 61 77 6b 20 27 2f 50 72 69 6e 63 69 70 61 6c 2f } //10 klist 2>/dev/null | awk '/Principal/
		$a_00_1 = {73 79 73 74 65 6d 5f 70 72 6f 66 69 6c 65 72 20 53 50 48 61 72 64 77 61 72 65 44 61 74 61 54 79 70 65 20 32 3e 2f 64 65 76 2f 6e 75 6c 6c 20 7c 20 61 77 6b 20 27 2f 50 72 6f 63 65 73 73 6f 72 20 4e 61 6d 65 } //10 system_profiler SPHardwareDataType 2>/dev/null | awk '/Processor Name
		$a_00_2 = {6d 64 35 20 7c 20 78 78 64 20 2d 72 20 2d 70 20 7c 20 62 61 73 65 36 34 } //10 md5 | xxd -r -p | base64
		$a_00_3 = {69 66 63 6f 6e 66 69 67 20 65 6e 30 20 7c 20 61 77 6b 20 27 2f 65 74 68 65 72 } //10 ifconfig en0 | awk '/ether
		$a_00_4 = {63 68 6d 6f 64 20 37 35 35 } //10 chmod 755
		$a_00_5 = {75 75 69 64 67 65 6e } //1 uuidgen
		$a_00_6 = {65 63 68 6f } //1 echo
		$a_00_7 = {73 65 6e 64 52 65 71 75 65 73 74 } //1 sendRequest
		$a_00_8 = {50 4f 53 54 } //1 POST
		$a_00_9 = {49 4f 50 6c 61 74 66 6f 72 6d 45 78 70 65 72 74 44 65 76 69 63 65 } //1 IOPlatformExpertDevice
		$a_00_10 = {49 4f 50 6c 61 74 66 6f 72 6d 53 65 72 69 61 6c 4e 75 6d 62 65 72 } //1 IOPlatformSerialNumber
		$a_00_11 = {49 4f 50 6c 61 74 66 6f 72 6d 55 55 49 44 } //1 IOPlatformUUID
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_00_3  & 1)*10+(#a_00_4  & 1)*10+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1) >=53
 
}