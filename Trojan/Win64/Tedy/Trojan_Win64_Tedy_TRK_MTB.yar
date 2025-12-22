
rule Trojan_Win64_Tedy_TRK_MTB{
	meta:
		description = "Trojan:Win64/Tedy.TRK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 53 49 bb ac 69 9e 57 bc d8 8e 9a 57 48 bf b0 d7 2a b4 80 e3 bf 24 66 41 8b fb 49 f7 d3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}