
rule Trojan_Win64_XWorm_GAPE_MTB{
	meta:
		description = "Trojan:Win64/XWorm.GAPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_81_0 = {37 2e 74 63 70 2e 65 75 2e 6e 67 72 6f 6b 2e 69 6f } //8 7.tcp.eu.ngrok.io
		$a_81_1 = {53 6f 63 6b 65 74 20 63 72 65 61 74 69 6f 6e } //1 Socket creation
	condition:
		((#a_81_0  & 1)*8+(#a_81_1  & 1)*1) >=9
 
}