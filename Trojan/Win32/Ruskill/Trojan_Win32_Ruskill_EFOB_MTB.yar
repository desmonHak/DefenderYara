
rule Trojan_Win32_Ruskill_EFOB_MTB{
	meta:
		description = "Trojan:Win32/Ruskill.EFOB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b f0 03 d6 03 ca 8b 15 ?? ?? ?? ?? 03 55 88 88 0a } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}