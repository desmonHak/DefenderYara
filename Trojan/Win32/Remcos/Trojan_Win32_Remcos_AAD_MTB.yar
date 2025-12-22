
rule Trojan_Win32_Remcos_AAD_MTB{
	meta:
		description = "Trojan:Win32/Remcos.AAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {42 8b 75 18 8a 8c 95 ?? ?? ?? ?? 8a 14 30 32 d1 88 14 30 40 3b c7 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}