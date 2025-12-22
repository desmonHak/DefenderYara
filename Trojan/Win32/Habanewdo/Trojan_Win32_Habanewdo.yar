
rule Trojan_Win32_Habanewdo{
	meta:
		description = "Trojan:Win32/Habanewdo,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {5c 00 43 00 4c 00 44 00 4d 00 53 00 47 00 50 00 4f 00 52 00 54 00 } //1 \CLDMSGPORT
		$a_00_1 = {47 00 4c 00 4f 00 42 00 41 00 4c 00 5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 52 00 50 00 43 00 20 00 43 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 } //1 GLOBAL\GLOBALROOT\RPC Control
		$a_03_2 = {ba a4 00 09 00 [0-10] ff 15 } //1
		$a_01_3 = {43 66 52 65 67 69 73 74 65 72 53 79 6e 63 52 6f 6f 74 } //1 CfRegisterSyncRoot
		$a_01_4 = {46 69 6c 74 65 72 53 65 6e 64 4d 65 73 73 61 67 65 } //1 FilterSendMessage
		$a_01_5 = {46 69 6c 74 65 72 43 6f 6e 6e 65 63 74 43 6f 6d 6d 75 6e 69 63 61 74 69 6f 6e 50 6f 72 74 } //1 FilterConnectCommunicationPort
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}