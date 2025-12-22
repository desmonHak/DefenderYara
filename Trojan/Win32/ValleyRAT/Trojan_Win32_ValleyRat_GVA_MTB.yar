
rule Trojan_Win32_ValleyRat_GVA_MTB{
	meta:
		description = "Trojan:Win32/ValleyRat.GVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {34 6e d0 06 84 2a 48 b6 69 d4 d1 52 ad } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}