
rule Trojan_BAT_Fareit_MCJ_MTB{
	meta:
		description = "Trojan:BAT/Fareit.MCJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {38 31 34 33 2d 64 36 63 66 30 65 37 35 37 66 30 64 00 00 0c 01 00 07 6e 65 77 61 73 73 6d } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}