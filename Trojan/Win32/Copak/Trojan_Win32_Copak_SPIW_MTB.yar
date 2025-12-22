
rule Trojan_Win32_Copak_SPIW_MTB{
	meta:
		description = "Trojan:Win32/Copak.SPIW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 31 17 81 c3 01 00 00 00 81 c7 02 00 00 00 81 c3 01 00 00 00 39 f7 7c } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}