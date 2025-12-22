
rule Trojan_Win32_Zusy_MKD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MKD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 c9 49 c1 e1 ?? 49 41 49 83 c1 ?? c1 e1 4d 59 0f b6 0c 32 0f b6 04 37 03 c8 } //15
		$a_03_1 = {8a 04 37 88 04 32 51 83 ?? ?? 31 c9 49 49 41 49 49 41 49 } //10
	condition:
		((#a_03_0  & 1)*15+(#a_03_1  & 1)*10) >=25
 
}