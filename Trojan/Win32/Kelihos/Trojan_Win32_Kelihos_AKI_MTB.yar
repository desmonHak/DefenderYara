
rule Trojan_Win32_Kelihos_AKI_MTB{
	meta:
		description = "Trojan:Win32/Kelihos.AKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 c0 40 8a cb d3 e0 8b 4d e8 85 c1 74 5a 8a c3 04 61 c7 45 ec 20 3a 5c 00 88 45 ec 8d 45 ec 50 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}