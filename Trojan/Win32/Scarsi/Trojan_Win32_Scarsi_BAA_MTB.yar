
rule Trojan_Win32_Scarsi_BAA_MTB{
	meta:
		description = "Trojan:Win32/Scarsi.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 08 03 55 fc 0f be 1a e8 ?? ?? ?? ?? 33 d8 8b 45 08 03 45 fc 88 18 eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}