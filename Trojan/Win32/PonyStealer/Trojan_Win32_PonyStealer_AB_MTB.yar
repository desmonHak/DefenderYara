
rule Trojan_Win32_PonyStealer_AB_MTB{
	meta:
		description = "Trojan:Win32/PonyStealer.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 75 6c 69 6e 00 00 41 6d 70 68 69 73 74 6f 6d 6f 69 64 31 00 01 00 02 00 00 28 40 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}