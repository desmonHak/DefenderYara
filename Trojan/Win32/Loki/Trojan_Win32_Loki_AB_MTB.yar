
rule Trojan_Win32_Loki_AB_MTB{
	meta:
		description = "Trojan:Win32/Loki.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {ff cc 31 00 00 d1 1c ?? 99 f5 55 59 43 be } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}