
rule TrojanDownloader_O97M_Donoff_ET{
	meta:
		description = "TrojanDownloader:O97M/Donoff.ET,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {70 3a 22 20 2b 20 22 2f 2f 22 20 2b 20 68 61 6d 6d 65 72 20 2b 20 22 2f } //1 p:" + "//" + hammer + "/
		$a_01_1 = {2e 65 78 22 20 2b 20 22 65 7d 29 29 } //1 .ex" + "e}))
		$a_01_2 = {67 61 6d 65 72 74 6f 6e 20 2b 20 22 65 22 } //1 gamerton + "e"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}