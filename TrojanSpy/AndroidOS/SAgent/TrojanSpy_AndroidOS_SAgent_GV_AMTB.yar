
rule TrojanSpy_AndroidOS_SAgent_GV_AMTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgent.GV!AMTB,SIGNATURE_TYPE_DEXHSTR_EXT,09 00 09 00 0c 00 00 "
		
	strings :
		$a_01_0 = {47 45 54 5f 50 57 44 45 44 } //1 GET_PWDED
		$a_01_1 = {73 74 61 72 74 54 72 61 63 6b 69 6e 67 } //1 startTracking
		$a_01_2 = {50 69 63 6b 43 6f 6e 74 61 63 74 } //1 PickContact
		$a_01_3 = {73 65 72 76 69 63 65 5f 68 65 61 72 74 62 65 61 74 } //1 service_heartbeat
		$a_01_4 = {73 65 6e 64 54 65 78 74 4d 65 73 73 61 67 65 } //1 sendTextMessage
		$a_01_5 = {74 61 6b 65 70 69 63 74 75 72 65 } //1 takepicture
		$a_01_6 = {57 61 6b 65 55 70 41 63 74 69 76 69 74 79 } //1 WakeUpActivity
		$a_01_7 = {53 45 4e 44 5f 53 4d 53 } //1 SEND_SMS
		$a_01_8 = {61 63 74 69 76 69 74 79 5f 73 63 72 65 65 6e 5f 6c 6f 63 6b 5f 70 77 64 } //1 activity_screen_lock_pwd
		$a_01_9 = {53 63 72 65 65 6e 4c 6f 63 6b 50 77 64 41 63 74 69 76 69 74 79 } //1 ScreenLockPwdActivity
		$a_01_10 = {63 61 70 74 75 72 65 43 61 6c 6c } //1 captureCall
		$a_01_11 = {41 75 64 69 6f 52 65 63 6f 72 64 65 72 53 65 72 76 69 63 65 } //1 AudioRecorderService
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1) >=9
 
}