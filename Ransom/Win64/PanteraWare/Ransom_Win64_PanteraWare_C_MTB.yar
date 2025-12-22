
rule Ransom_Win64_PanteraWare_C_MTB{
	meta:
		description = "Ransom:Win64/PanteraWare.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 01 83 f2 ?? 88 14 08 48 ff c1 48 39 cb 7f } //10
		$a_01_1 = {44 65 6c 65 74 65 53 68 61 64 6f 77 43 6f 70 79 41 63 74 69 6f 6e } //5 DeleteShadowCopyAction
		$a_01_2 = {47 65 74 53 68 61 64 6f 77 43 6f 70 79 49 6e 66 6f 56 73 73 } //5 GetShadowCopyInfoVss
		$a_01_3 = {53 65 6c 66 44 65 6c 65 74 65 } //5 SelfDelete
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5+(#a_01_3  & 1)*5) >=25
 
}