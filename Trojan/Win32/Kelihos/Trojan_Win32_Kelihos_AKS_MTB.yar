
rule Trojan_Win32_Kelihos_AKS_MTB{
	meta:
		description = "Trojan:Win32/Kelihos.AKS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {68 b0 33 40 00 57 ff d6 68 bc 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 cc 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 d8 33 40 00 57 a3 ?? ?? ?? ?? ff d6 68 e0 33 40 00 57 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}