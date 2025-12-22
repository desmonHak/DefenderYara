
rule Trojan_Win64_Amadey_GSS_MTB{
	meta:
		description = "Trojan:Win64/Amadey.GSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 f2 48 03 15 ?? ?? ?? ?? 89 d8 c1 f8 1f c1 e8 1b 01 c3 83 e3 1f 29 c3 48 63 db 0f b6 04 1f 30 02 48 83 c6 01 48 81 fe 4b 4e 07 00 74 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}