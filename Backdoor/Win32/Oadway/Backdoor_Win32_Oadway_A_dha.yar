
rule Backdoor_Win32_Oadway_A_dha{
	meta:
		description = "Backdoor:Win32/Oadway.A!dha,SIGNATURE_TYPE_PEHSTR,14 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 fc 8b 4d f4 8b 14 81 8b 45 f8 8d 8c 10 dc 00 00 00 39 4d e4 77 02 } //10
		$a_01_1 = {8b 55 fc 0f af 55 f8 8b 45 08 0f be 08 03 d1 89 55 fc 8b 55 08 83 c2 01 89 55 08 } //10
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}