
rule Trojan_BAT_OrcusRat_A_AMTB{
	meta:
		description = "Trojan:BAT/OrcusRat.A!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4f 72 63 75 73 2e 53 68 61 72 65 64 2e 43 6f 6d 6d 61 6e 64 73 2e 52 65 67 69 73 74 72 79 } //Orcus.Shared.Commands.Registry  1
		$a_80_1 = {4f 72 63 75 73 2e 53 65 72 76 69 63 65 2e 70 64 62 } //Orcus.Service.pdb  1
		$a_80_2 = {4f 72 63 75 73 2e 53 65 72 76 69 63 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //Orcus.Service.Properties.Resources  1
		$a_80_3 = {4f 72 63 75 73 55 74 69 6c 69 74 69 65 73 } //OrcusUtilities  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}