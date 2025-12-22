
rule Trojan_Win64_TofuStation_F_dha{
	meta:
		description = "Trojan:Win64/TofuStation.F!dha,SIGNATURE_TYPE_PEHSTR,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {49 6e 69 74 3a 20 4b 65 72 6e 65 6c 20 69 6e 69 74 69 61 6c 69 73 65 64 } //1 Init: Kernel initialised
		$a_01_1 = {49 6e 69 74 3a 20 53 65 74 74 69 6e 67 20 73 65 74 74 6e 69 67 73 } //1 Init: Setting settnigs
		$a_01_2 = {53 65 72 76 69 63 65 57 6f 72 6b 65 72 54 68 72 65 61 64 3a 20 49 6e 69 74 20 69 73 20 73 75 63 63 65 73 73 66 75 6c 6c 2c 20 65 6e 74 72 69 6e 67 20 6d 61 69 6e 20 6c 6f 6f 70 } //1 ServiceWorkerThread: Init is successfull, entring main loop
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}