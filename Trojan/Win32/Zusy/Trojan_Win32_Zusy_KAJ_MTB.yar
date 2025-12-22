
rule Trojan_Win32_Zusy_KAJ_MTB{
	meta:
		description = "Trojan:Win32/Zusy.KAJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 03 00 00 "
		
	strings :
		$a_03_0 = {89 10 b2 6e 86 d6 88 70 04 b2 65 86 d6 88 70 08 51 b9 ?? ?? ?? ?? 87 d1 29 10 } //20
		$a_01_1 = {ac 88 07 47 84 c0 75 } //10
		$a_01_2 = {8b c8 33 ca 8b c1 b9 00 00 00 00 83 c1 04 49 b8 04 00 00 00 } //5
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10+(#a_01_2  & 1)*5) >=35
 
}