
rule Trojan_BAT_AsyncRAT_JX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.JX!MTB,SIGNATURE_TYPE_PEHSTR,0e 00 0e 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 00 3d 00 67 00 49 00 6b 00 56 00 6d 00 64 00 70 00 56 00 32 00 59 00 6c 00 4a 00 6c 00 49 00 } //3 ==gIkVmdpV2YlJlI
		$a_01_1 = {45 6e 63 72 79 70 74 58 6f 72 } //2 EncryptXor
		$a_01_2 = {47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 } //2 GetAsyncKeyState
		$a_01_3 = {47 65 74 4b 65 79 53 74 61 74 65 } //2 GetKeyState
		$a_01_4 = {52 65 67 69 73 74 72 79 4b 65 79 50 65 72 6d 69 73 73 69 6f 6e 43 68 65 63 6b } //2 RegistryKeyPermissionCheck
		$a_01_5 = {50 72 65 76 65 6e 74 53 6c 65 65 70 } //2 PreventSleep
		$a_01_6 = {4b 65 65 70 41 6c 69 76 65 50 61 63 6b 65 74 } //1 KeepAlivePacket
		$a_01_7 = {78 00 78 00 78 00 2e 00 31 00 76 00 31 00 76 00 31 00 76 00 2e 00 63 00 6f 00 6d 00 } //1 xxx.1v1v1v.com
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=14
 
}