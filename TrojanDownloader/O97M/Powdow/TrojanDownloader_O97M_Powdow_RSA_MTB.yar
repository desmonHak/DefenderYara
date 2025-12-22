
rule TrojanDownloader_O97M_Powdow_RSA_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RSA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 28 27 68 74 27 2b 27 74 27 2b 27 70 27 2b 27 73 3a 2f 27 2b 27 2f 69 61 34 30 32 2e } //1 =('ht'+'t'+'p'+'s:/'+'/ia402.
		$a_01_1 = {3d 20 43 68 72 28 38 30 29 20 26 20 22 6c 61 63 65 28 27 45 54 } //1 = Chr(80) & "lace('ET
		$a_01_2 = {75 73 27 2b 27 2e 61 27 2b 27 72 63 2e 69 27 2b 27 6f 27 2b 27 2f 27 2b 27 74 61 72 79 2e 74 27 2b 27 78 74 27 29 3b 24 } //1 us'+'.a'+'rc.i'+'o'+'/'+'tary.t'+'xt');$
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}