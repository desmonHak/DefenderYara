
rule Trojan_Win32_Barys_ABR_MTB{
	meta:
		description = "Trojan:Win32/Barys.ABR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d3 51 33 c0 80 3a 00 74 0c 0f b6 0a d3 c0 03 c1 d3 c0 42 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}