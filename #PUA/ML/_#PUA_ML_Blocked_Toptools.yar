
rule _#PUA_ML_Blocked_Toptools{
	meta:
		description = "!#PUA:ML:Blocked:Toptools,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 00 68 00 65 00 73 00 63 00 72 00 65 00 65 00 6e 00 73 00 6e 00 61 00 70 00 73 00 68 00 6f 00 74 00 2e 00 63 00 6f 00 6d 00 } //1 thescreensnapshot.com
		$a_01_1 = {5c 43 6f 6d 6d 6f 6e 5c 49 31 38 4e 5c 63 6f 6e 66 2e 64 62 } //1 \Common\I18N\conf.db
		$a_01_2 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 4d 00 75 00 74 00 65 00 78 00 5f 00 54 00 4f 00 4f 00 4c 00 53 00 49 00 31 00 38 00 4e 00 47 00 55 00 49 00 44 00 5f 00 } //1 Global\Mutex_TOOLSI18NGUID_
		$a_01_3 = {53 63 72 65 65 6e 53 6e 61 70 73 68 6f 74 2e 70 64 62 } //1 ScreenSnapshot.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}