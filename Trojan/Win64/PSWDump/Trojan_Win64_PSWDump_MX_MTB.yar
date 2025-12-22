
rule Trojan_Win64_PSWDump_MX_MTB{
	meta:
		description = "Trojan:Win64/PSWDump.MX!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 8b 03 48 85 c0 74 09 e8 22 07 01 00 85 c0 75 0b 48 83 c3 08 48 3b df 75 e6 33 c0 48 8b 5c 24 30 48 83 c4 20 } //1
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 44 00 65 00 63 00 72 00 79 00 70 00 74 00 57 00 6f 00 72 00 6b 00 44 00 6f 00 6e 00 65 00 45 00 76 00 65 00 6e 00 74 00 } //1 Global\ChromeDecryptWorkDoneEvent
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}