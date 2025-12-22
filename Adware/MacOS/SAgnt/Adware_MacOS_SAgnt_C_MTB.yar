
rule Adware_MacOS_SAgnt_C_MTB{
	meta:
		description = "Adware:MacOS/SAgnt.C!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 69 72 65 54 77 65 61 6b 54 75 6e 65 75 70 48 69 74 3a 66 6f 72 54 68 65 50 72 6f 64 75 63 74 3a 74 6f 50 72 6f 64 75 63 74 49 64 3a 66 72 6f 6d 50 72 6f 64 75 63 74 49 64 } //1 fireTweakTuneupHit:forTheProduct:toProductId:fromProductId
		$a_01_1 = {67 6f 54 6f 54 77 65 61 6b 41 6e 64 54 75 6e 65 75 70 } //1 goToTweakAndTuneup
		$a_01_2 = {2f 41 70 70 6c 69 63 61 74 69 6f 6e 73 2f 44 69 73 6b 20 43 6c 65 61 6e 20 50 72 6f 2e 61 70 70 } //1 /Applications/Disk Clean Pro.app
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}