
rule Trojan_Win64_Shellcoderunner_AMTB{
	meta:
		description = "Trojan:Win64/Shellcoderunner!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_80_0 = {2f 66 6f 6e 74 61 77 65 73 6f 6d 65 5f 74 6c 64 2e 77 6f 66 66 } ///fontawesome_tld.woff  2
		$a_80_1 = {25 73 64 6f 63 75 6d 65 6e 74 5f 25 30 34 64 25 30 32 64 25 30 32 64 5f 25 30 32 64 25 30 32 64 25 30 32 64 2e 70 64 66 } //%sdocument_%04d%02d%02d_%02d%02d%02d.pdf  2
	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*2) >=4
 
}