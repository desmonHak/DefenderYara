
rule Ransom_Win32_RozaLocker_MKV_MTB{
	meta:
		description = "Ransom:Win32/RozaLocker.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 "
		
	strings :
		$a_03_0 = {56 53 83 ec 04 8b 5c 24 10 8b 74 24 14 0f b6 43 1d 89 04 24 e8 ?? ?? ?? ?? 32 06 30 03 0f b6 43 1e 89 04 24 e8 } //5
		$a_01_1 = {52 6f 7a 61 2d 4c 6f 63 6b 65 72 } //3 Roza-Locker
		$a_01_2 = {2e 72 6d 6c 6f 63 6b } //2 .rmlock
		$a_01_3 = {52 65 61 64 4d 65 2e 74 78 74 } //1 ReadMe.txt
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=11
 
}