
rule TrojanDownloader_Win32_Jaik_ARA_MTB{
	meta:
		description = "TrojanDownloader:Win32/Jaik.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {0f b6 95 57 fc ff ff 83 f2 36 0f b6 45 d0 33 d0 88 95 57 fc ff ff 8b 4d ac 03 4d d0 8a 95 57 fc ff ff 88 11 e9 5b ff ff ff } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}