
rule Trojan_Win32_Copak_BAE_MTB{
	meta:
		description = "Trojan:Win32/Copak.BAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {09 cf 09 cf 29 cf 31 13 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 0c 24 83 c4 04 81 c3 02 00 00 00 41 39 f3 7c } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}