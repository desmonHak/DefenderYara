
rule Trojan_Win32_BadAudio_DA_MTB{
	meta:
		description = "Trojan:Win32/BadAudio.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 04 00 00 "
		
	strings :
		$a_03_0 = {c1 c5 19 c1 c7 0e 01 ?? ?? ?? 31 ef c1 eb 03 31 } //10
		$a_03_1 = {c1 c7 0f 8b ?? ?? ?? ?? ?? c1 c3 0d 31 fb c1 ea 0a 31 } //10
		$a_81_2 = {53 79 73 74 65 6d 46 75 6e 63 74 69 6f 6e 30 33 36 } //1 SystemFunction036
		$a_81_3 = {36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 36 5c 5c 5c 5c 5c 5c 5c 5c 5c } //1 6666666666666666\\\\\\\\\
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=22
 
}