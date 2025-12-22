
rule Trojan_Win32_Bayrob_NB_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0f b7 51 02 83 c1 02 0f b7 34 0f 2b f2 74 ec } //2
		$a_01_1 = {0f b7 11 8b c2 0f b7 37 2b f0 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}