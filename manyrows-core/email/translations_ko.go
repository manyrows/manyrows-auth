package email

// Korean (ko) email template translations. Registered into the package-level
// translations map at init time so the existing English catalog
// (translations.go) stays untouched. Keys MUST match the "en" map
// byte-for-byte: T() falls back to English per key.
//
// The `{brand}` token (not a printf verb) is preserved verbatim — T()
// substitutes it with the operator-configured brand name at render time.
// printf placeholders (%s, …) are preserved in the same order as English,
// since each Korean body keeps the English argument sequence.
func init() {
	translations["ko"] = map[string]string{
		// Admin registration
		"admin.register.subject": "{brand} 매직 링크",
		"admin.register.body":    "안녕하세요,\n\n이 매직 링크를 사용하여 {brand} 계정 등록을 완료하세요:\n\n%s\n\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Admin login
		"admin.login.subject": "{brand} 로그인 링크",
		"admin.login.body":    "안녕하세요,\n\n이 매직 링크를 사용하여 {brand}에 로그인하세요:\n\n%s\n\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Workspace OTP
		"workspace.otp.subject": "%s 로그인 코드",
		"workspace.otp.body":    "%s의 로그인 코드입니다:\n\n%s\n\n이 코드는 10분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.",

		// App magic link (end-user sign-in via one-click link)
		"apps.magicLink.subject": "%s 로그인 링크",
		"apps.magicLink.body":    "안녕하세요,\n\n이 링크를 사용하여 %s에 로그인하세요:\n\n%s\n\n이 링크는 15분 후에 만료되며 한 번만 사용할 수 있습니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Admin email validation
		"admin.validation.subject": "{brand} 인증 코드",
		"admin.validation.body":    "인증 코드입니다:\n\n%s\n\n이 코드는 15분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.",

		// Admin password reset
		"admin.password_reset.subject": "{brand} 비밀번호 재설정 코드",
		"admin.password_reset.body":    "안녕하세요,\n\n이 코드를 사용하여 {brand} 비밀번호를 재설정하세요:\n\n%s\n\n이 코드는 15분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Workspace password reset
		"workspace.password_reset.subject": "%s 비밀번호 재설정 코드",
		"workspace.password_reset.body":    "안녕하세요,\n\n이 코드를 사용하여 %s 비밀번호를 재설정하세요:\n\n%s\n\n이 코드는 15분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Email change (admin)
		"email_change.subject": "새 {brand} 이메일 주소를 인증하세요",
		"email_change.body":    "안녕하세요,\n\n{brand} 계정 이메일을 이 주소로 변경하도록 요청하셨습니다.\n\n인증 코드입니다:\n\n%s\n\n이 코드는 15분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.\n",

		// Email change (workspace/app user)
		"workspace.email_change.subject": "%s 이메일 변경 코드",
		"workspace.email_change.body":    "%s 이메일 변경 인증 코드입니다:\n\n%s\n\n이 코드는 15분 후에 만료됩니다.\n요청하지 않으셨다면 이 이메일을 무시하셔도 됩니다.",

		// Email change — notification sent to the OLD address after a
		// successful swap. Lets an account-takeover victim notice the
		// change before the attacker can pivot deeper. Doesn't contain
		// the new address — that would help the attacker confirm
		// where the account moved.
		"workspace.email_change.notice.subject": "%s 이메일 주소가 변경되었습니다",
		"workspace.email_change.notice.body":    "%s 계정의 이메일 주소가 방금 변경되었습니다.\n\n본인이 변경하셨다면 별도의 조치가 필요하지 않습니다.\n\n본인이 변경하지 않으셨다면 즉시 워크스페이스 관리자에게 문의해 주세요. 계정이 탈취되었을 수 있습니다.",
		"email_change.notice.subject":           "{brand} 이메일 주소가 변경되었습니다",
		"email_change.notice.body":              "{brand} 계정의 이메일 주소가 방금 변경되었습니다.\n\n본인이 변경하셨다면 별도의 조치가 필요하지 않습니다.\n\n본인이 변경하지 않으셨다면 이 이메일에 회신해 주세요. 계정 접근 복구를 도와드리겠습니다.",

		// Team invite
		"team_invite.subject": "{brand}의 %s에 초대되었습니다",
		"team_invite.body":    "안녕하세요,\n\n%s님이 회원님을 {brand}의 \"%s\" 관리자로 초대했습니다.\n\n아래 링크를 클릭하여 초대를 수락하고 계정을 만드세요:\n\n%s\n\n이 링크는 7일 후에 만료됩니다.\n예상하지 못한 초대라면 이 이메일을 무시하셔도 됩니다.\n",

		// User invite (app user)
		"user_invite.subject": "%s에 추가되었습니다",
		"user_invite.body":    "안녕하세요,\n\n회원님이 %s에 추가되었습니다.\n\n시작하려면 앱에 접속하여 로그인하세요:\n\n%s\n\n아직 비밀번호가 없다면 로그인 페이지에서 \"비밀번호 찾기\"를 클릭하여 설정하세요.\n",
	}
}
