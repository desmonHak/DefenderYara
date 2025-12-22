
rule Trojan_Win32_Bayrob_NA_MTB{
	meta:
		description = "Trojan:Win32/Bayrob.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 75 0c 8a 06 49 88 02 42 46 85 c9 } //2
		$a_01_1 = {8b 72 04 41 2b f0 3b ce 7c e6 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}