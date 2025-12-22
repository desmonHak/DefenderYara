
rule Ransom_Win32_SafePay_MKV_MTB{
	meta:
		description = "Ransom:Win32/SafePay.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {32 02 32 c1 34 71 88 44 0d cf 41 83 f9 11 72 ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}