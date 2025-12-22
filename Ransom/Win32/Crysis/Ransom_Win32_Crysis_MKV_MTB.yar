
rule Ransom_Win32_Crysis_MKV_MTB{
	meta:
		description = "Ransom:Win32/Crysis.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f8 8d 8f 00 72 01 00 8d 74 26 00 30 10 30 50 01 83 c0 02 39 c8 75 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}