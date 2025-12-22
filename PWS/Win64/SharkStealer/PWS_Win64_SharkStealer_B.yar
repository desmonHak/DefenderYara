
rule PWS_Win64_SharkStealer_B{
	meta:
		description = "PWS:Win64/SharkStealer.B,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {3a 73 68 61 72 6b 5f [0-06] 3a } //2
		$a_01_1 = {62 6c 79 61 64 67 65 74 3a } //1 blyadget:
		$a_01_2 = {65 78 74 2e 7a 69 70 } //1 ext.zip
		$a_01_3 = {65 74 68 5f 63 61 6c 6c } //1 eth_call
		$a_01_4 = {63 6f 6e 6e 65 63 74 54 6f 53 65 72 76 65 72 } //1 connectToServer
		$a_03_5 = {83 fa 05 75 ?? 81 39 68 74 74 70 75 ?? 80 79 04 73 75 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}