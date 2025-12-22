
rule Trojan_Win32_Fragtor_LME_MTB{
	meta:
		description = "Trojan:Win32/Fragtor.LME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {b0 01 84 c0 79 ?? 81 c2 00 58 47 f8 89 54 24 08 83 d1 0d 89 4c 24 0c } //20
		$a_01_1 = {8b 4d e4 83 c4 0c 8b 45 dc 03 c0 c6 45 ef 01 89 71 30 66 89 41 2c 66 89 79 2e 8b 4d e0 83 f9 07 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}