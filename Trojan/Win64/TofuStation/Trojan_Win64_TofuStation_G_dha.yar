
rule Trojan_Win64_TofuStation_G_dha{
	meta:
		description = "Trojan:Win64/TofuStation.G!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2e 20 43 75 72 72 65 6e 74 20 53 74 61 74 75 73 3a } //1 . Current Status:
		$a_01_1 = {43 3a 5c 73 65 72 76 69 63 65 5f 6c 6f 67 2e 74 78 74 } //1 C:\service_log.txt
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}