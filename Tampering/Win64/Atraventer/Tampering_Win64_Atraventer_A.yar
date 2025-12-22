
rule Tampering_Win64_Atraventer_A{
	meta:
		description = "Tampering:Win64/Atraventer.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_43_0 = {56 53 48 81 ec 90 90 02 00 00 e8 90 01 04 48 0f bf 15 90 01 04 41 b9 97 96 ff ff 90 00 00 } //1
	condition:
		((#a_43_0  & 1)*1) >=1
 
}