local lua_util = require "lua_util"
local lua_settings = require "lua_settings"
local rspamd_kann = require "rspamd_kann"
local ucl = require "ucl"
local argparse = require "argparse"
local rspamd_logger = require "rspamd_logger"
local rspamd_task = require "rspamd_task"

local SPAM_LABEL = -1
local HAM_LABEL = 1

local all_symbols = {
	"INVALID_MSGID_ALLOWED",
	"FROM_NEEDS_ENCODING",
	"ASN",
	"DMARC_POLICY_ALLOW",
	"MISSING_MID",
	"HAS_WP_URI",
	"MAILER_1C_8",
	"ENVFROM_INVALID",
	"MID_RHS_WWW",
	"REPLYTO_DOM_NEQ_FROM_DOM",
	"HAS_X_SOURCE",
	"SPF_FAIL_FORWARDING",
	"RCVD_IN_DNSWL_MED",
	"MIME_MA_MISSING_HTML",
	"MV_CASE",
	"RCPT_COUNT_THREE",
	"FORGED_RECIPIENTS",
	"PHP_SCRIPT_ROOT",
	"HAS_X_GMSV",
	"LEAKED_PASSWORD_SCAM",
	"DBL_PROHIBIT",
	"FAKE_RECEIVED_mail_ru",
	"DISPOSABLE_TO",
	"X_PHPOS_FAKE",
	"HEADER_REPLYTO_EMPTY_DELIMITER",
	"MID_MISSING_BRACKETS",
	"SURBL_MULTI_FAIL",
	"FORGED_CALLBACK",
	"R_SAJDING",
	"GREYLIST_SAVE",
	"INFO_TO_INFO_LU",
	"MSBL_EBL_GREY",
	"WP_COMPROMISED",
	"RBL_SPAMHAUS_XBL",
	"KLMS_SPAM",
	"PDF_JAVASCRIPT",
	"RCPT_COUNT_GT_50",
	"FM_FAKE_HELO_VERIZON",
	"RBL_SENDERSCORE",
	"RCVD_DOUBLE_IP_SPAM",
	"HAS_GUC_PROXY_URI",
	"FORGED_MUA_POSTBOX_MSGID_UNKNOWN",
	"URIBL_MULTI",
	"BAYES_SPAM",
	"FWD_MAILRU",
	"HIDDEN_SOURCE_OBJ",
	"HFILTER_HELO_IP_A",
	"MIME_ARCHIVE_IN_ARCHIVE",
	"FORGED_MUA_MAILLIST",
	"FORGED_OUTLOOK_TAGS",
	"URIBL_GREY",
	"HEADER_FORGED_MDN",
	"URIBL_BLACK",
	"RBL_VIRUSFREE_UNKNOWN",
	"RBL_SPAMHAUS_XBL_ANY",
	"SUBJECT_HAS_CURRENCY",
	"HTTP_TO_HTTPS",
	"MIME_GOOD",
	"MIME_HTML_ONLY",
	"SUSPICIOUS_BOUNDARY4",
	"R_EMPTY_IMAGE",
	"STOX_REPLY_TYPE",
	"HAS_XAW",
	"MSBL_EBL",
	"SUBJECT_ENDS_QUESTION",
	"FWD_YANDEX",
	"HAS_REPLYTO",
	"PDF_ENCRYPTED",
	"R_SPF_SOFTFAIL",
	"NEURAL_HAM",
	"MAILSPIKE",
	"RBL_SEM",
	"FORGED_MUA_THEBAT_BOUN",
	"REPLYTO_EQ_TO_ADDR",
	"HAS_X_AS",
	"SIGNED_PGP",
	"HFILTER_HOSTNAME_3",
	"RBL_SPAMHAUS_PBL",
	"DMARC_POLICY_REJECT",
	"MW_SURBL_MULTI",
	"SUSPICIOUS_BOUNDARY2",
	"TAGGED_FROM",
	"MAILSPIKE_FAIL",
	"HFILTER_HELO_5",
	"HFILTER_FROMHOST_NORESOLVE_MX",
	"LEAKED_PASSWORD_SCAM_RE",
	"XAW_SERVICE_ACCT",
	"REPLYTO_EXCESS_QP",
	"RBL_SPAMHAUS_BLOCKED",
	"REPLYTO_EQ_FROM",
	"SEM_URIBL_UNKNOWN_FAIL",
	"WHITELIST_SPF",
	"MIME_EXE_IN_GEN_SPLIT_RAR",
	"FROM_NEQ_DISPLAY_NAME",
	"FROM_DN_EQ_ADDR",
	"REPLIES_SET",
	"FORGED_SENDER",
	"SURBL_BLOCKED",
	"HAS_X_ANTIABUSE",
	"PHP_XPS_PATTERN",
	"BROKEN_HEADERS_MAILLIST",
	"FORGED_MUA_OPERA_MSGID",
	"MID_BARE_IP",
	"AUTOGEN_PHP_SPAMMY",
	"HFILTER",
	"DBL_MALWARE",
	"FROM_NAME_HAS_TITLE",
	"DBL_SPAM",
	"MISSING_DATE",
	"RATWARE_MS_HASH",
	"BLACKLIST_DMARC",
	"RSPAMD_URIBL_FAIL",
	"REPLYTO_DN_EQ_FROM_DN",
	"FROM_DISPLAY_CALLBACK",
	"REDIRECTOR_FALSE",
	"RECEIVED_SPAMHAUS_PBL",
	"CTYPE_MIXED_BOGUS",
	"DWL_DNSWL_MED",
	"RBL_SEM_IPV6_FAIL",
	"HFILTER_FROM_BOUNCE",
	"SPAM_FLAG",
	"FORGED_MUA_THUNDERBIRD_MSGID_UNKNOWN",
	"RCVD_DKIM_ARC_DNSWL_HI",
	"ENCRYPTED_PGP",
	"FORGED_GENERIC_RECEIVED2",
	"RCVD_TLS_ALL",
	"CRACKED_SURBL",
	"R_MIXED_CHARSET",
	"UNDISC_RCPTS_BULK",
	"FROM_NEQ_ENVFROM",
	"FORGED_MUA_THEBAT_MSGID_UNKNOWN",
	"RCVD_COUNT_ONE",
	"FORGED_MUA_THUNDERBIRD_MSGID",
	"GREYLIST_CHECK",
	"FROM_NO_DN",
	"FORGED_MUA_MOZILLA_MAIL_MSGID_UNKNOWN",
	"RBL_CALLBACK",
	"DBL_ABUSE",
	"RCVD_IN_DNSWL_HI",
	"RATELIMIT_UPDATE",
	"FORGED_GENERIC_RECEIVED",
	"DISPOSABLE_ENVFROM",
	"R_PARTS_DIFFER",
	"R_SUSPICIOUS_IMAGES",
	"SEM_URIBL_FRESH15_UNKNOWN_FAIL",
	"INVALID_MSGID",
	"SURBL_MULTI",
	"PDF_TIMEOUT",
	"PHISHED_OPENPHISH",
	"BAD_REP_POLICIES",
	"RBL_VIRUSFREE_UNKNOWN_FAIL",
	"MIME_ENCRYPTED_ARCHIVE",
	"RCVD_COUNT_THREE",
	"RCVD_ILLEGAL_CHARS",
	"HAS_X_PRIO_FIVE",
	"REPLYTO_EXCESS_BASE64",
	"FORGED_GENERIC_RECEIVED3",
	"HFILTER_HELO_NORES_A_OR_MX",
	"XM_UA_NO_VERSION",
	"BLOCKLISTDE_CHECK",
	"MAILER_1C_8_BASE64",
	"HFILTER_HELO_NOT_FQDN",
	"KNOWN_MID",
	"FORGED_RECIPIENTS_MAILLIST",
	"HFILTER_URL_ONLY",
	"MISSING_MIME_VERSION",
	"RBL_SPAMHAUS",
	"RCPT_COUNT_FIVE",
	"SUBJ_EXCESS_BASE64",
	"MID_RHS_IP_LITERAL",
	"ENCRYPTED_SMIME",
	"BLACKLIST_DKIM",
	"HTML_SHORT_LINK_IMG_1",
	"DATE_IN_PAST",
	"FWD_SRS",
	"REPLYTO_DOM_EQ_FROM_DOM",
	"TO_MATCH_ENVRCPT_ALL",
	"URL_IN_SUBJECT",
	"RBL_CALLBACK_WHITE",
	"AUTH_NA",
	"HFILTER_HELO_BADIP",
	"FUZZY_CALLBACK",
	"MIME_HEADER_CTYPE_ONLY",
	"WHITELIST_DKIM",
	"HAS_X_POS",
	"TRACKER_ID",
	"RBL_VIRUSFREE_BOTNET",
	"R_SPF_FAIL",
	"RCVD_VIA_SMTP_AUTH",
	"ZERO_FONT",
	"MIME_UNKNOWN",
	"MIME_BAD_ATTACHMENT",
	"HTML_SHORT_LINK_IMG_3",
	"RCVD_COUNT_FIVE",
	"DMARC_NA",
	"HISTORY_SAVE",
	"MISSING_SUBJECT",
	"MULTIPLE_UNIQUE_HEADERS",
	"HFILTER_HOSTNAME_UNKNOWN",
	"R_SPF_ALLOW",
	"FROM_EQ_ENVFROM",
	"RECEIVED_SPAMHAUS_CSS",
	"FROM_INVALID",
	"SETTINGS_CHECK",
	"DATE_IN_FUTURE",
	"EXT_CSS",
	"DWL_DNSWL_NONE",
	"DBL_FAIL",
	"PHISH_EMOTION",
	"EMPTY_SUBJECT",
	"RCVD_HELO_USER",
	"STRONGMAIL",
	"BITCOIN_ADDR",
	"MIME_MA_MISSING_TEXT",
	"WHITELIST_SPF_DKIM",
	"RWL_MAILSPIKE_NEUTRAL",
	"ASN_CHECK",
	"DMARC_BAD_POLICY",
	"DNSWL_BLOCKED",
	"BLACKLIST_SPF",
	"GOOGLE_FORWARDING_MID_MISSING",
	"FROM_NAME_EXCESS_SPACE",
	"R_MISSING_CHARSET",
	"HAS_INTERSPIRE_SIG",
	"CC_EXCESS_QP",
	"R_SPF_PERMFAIL",
	"TAGGED_RCPT",
	"CHECK_TO_CC",
	"HTML_VISIBLE_CHECKS",
	"RCVD_IN_DNSWL_LOW",
	"SEM_URIBL_FRESH15_UNKNOWN",
	"RDNS_DNSFAIL",
	"UNITEDINTERNET_SPAM",
	"RCVD_UNAUTH_PBL",
	"PHISHED_PHISHTANK",
	"RBL_MAILSPIKE_WORST",
	"PDF_SUSPICIOUS",
	"MIME_BASE64_TEXT_BOGUS",
	"R_WHITE_ON_WHITE",
	"HEADER_DATE_EMPTY_DELIMITER",
	"DBL_ABUSE_MALWARE",
	"HAS_GOOGLE_REDIR",
	"FROM_SERVICE_ACCT",
	"URIBL_RED",
	"FORGED_MUA_POSTBOX_MSGID",
	"SUBJECT_HAS_EXCLAIM",
	"R_DKIM_TEMPFAIL",
	"TO_EXCESS_BASE64",
	"NEURAL_SPAM",
	"HFILTER_HOSTNAME_1",
	"ABUSE_SURBL",
	"IP_SCORE_FREEMAIL",
	"HFILTER_FROMHOST_NORES_A_OR_MX",
	"DISPOSABLE_FROM",
	"HAS_ONION_URI",
	"HTML_SHORT_LINK_IMG_2",
	"VIOLATED_DIRECT_SPF",
	"AOL_SPAM",
	"DIRECT_TO_MX",
	"FREEMAIL_TO",
	"FORGED_SENDER_FORWARDING",
	"RBL_MAILSPIKE_VERYBAD",
	"TO_EQ_FROM",
	"SUSPICIOUS_BOUNDARY",
	"SPOOF_DISPLAY_NAME",
	"RECEIVED_SPAMHAUS_DROP",
	"ARC_ALLOW",
	"KNOWN_NO_MID",
	"DBL_BLOCKED",
	"GOOGLE_FORWARDING_MID_BROKEN",
	"RBL_NIXSPAM",
	"FORGED_MUA_MOZILLA_MAIL_MSGID",
	"XM_CASE",
	"RCVD_IN_DNSWL_NONE",
	"REPLY",
	"INVALID_POSTFIX_RECEIVED",
	"TO_DN_EQ_ADDR_ALL",
	"MIME_BAD",
	"HFILTER_HELO_3",
	"RBL_MAILSPIKE_BAD",
	"FAKE_REPLY",
	"TO_DN_NONE",
	"TO_DN_EQ_ADDR_SOME",
	"PHISHING",
	"DMARC_POLICY_QUARANTINE",
	"RCVD_COUNT_ZERO",
	"MAIL_RU_MAILER_BASE64",
	"FREEMAIL_REPLYTO_NEQ_FROM_DOM",
	"FUZZY_DENIED",
	"FUZZY_PROB",
	"FAKE_RECEIVED_smtp_yandex_ru",
	"HAS_ORG_HEADER",
	"MIME_BAD_EXTENSION",
	"INTRODUCTION",
	"CT_EXTRA_SEMI",
	"R_DKIM_ALLOW",
	"HFILTER_HELO_BAREIP",
	"TO_WRAPPED_IN_SPACES",
	"MID_CONTAINS_TO",
	"R_UNDISC_RCPT",
	"RBL_SPAMHAUS_CSS",
	"HAS_XOIP",
	"MANY_INVISIBLE_PARTS",
	"DISPOSABLE_CC",
	"DISPOSABLE_ENVRCPT",
	"BROKEN_HEADERS",
	"PH_SURBL_MULTI",
	"MISSING_TO",
	"FREEMAIL_ENVRCPT",
	"MISSING_MID_ALLOWED",
	"RCVD_COUNT_TWO",
	"MID_RHS_MATCH_FROM",
	"SUBJ_EXCESS_QP",
	"CHECK_REPLYTO",
	"HEADER_CC_EMPTY_DELIMITER",
	"SEM_URIBL",
	"FUZZY_UNKNOWN",
	"RCPT_COUNT_ONE",
	"RCPT_COUNT_TWELVE",
	"RBL_SPAMHAUS_BLOCKED_OPENRESOLVER",
	"FORGED_GENERIC_RECEIVED4",
	"DKIM_SIGNED",
	"CHECK_MIME",
	"TO_DN_RECIPIENTS",
	"HEADER_CC_DELIMITER_TAB",
	"MISSING_FROM",
	"HAS_ANON_DOMAIN",
	"DMARC_DNSFAIL",
	"FROM_EXCESS_BASE64",
	"YANDEX_RU_MAILER_CTYPE_MIXED_BOGUS",
	"MILTER_HEADERS",
	"HEADER_RCONFIRM_MISMATCH",
	"INVALID_FROM_8BIT",
	"EMAIL_PLUS_ALIASES",
	"CHECK_RCVD",
	"PDF_LONG_TRAILER",
	"FWD_GOOGLE",
	"HEADER_DATE_DELIMITER_TAB",
	"DISPOSABLE_REPLYTO",
	"REPLYTO_ADDR_EQ_FROM",
	"FORGED_MUA_OUTLOOK",
	"FORGED_MUA_KMAIL_MSGID_UNKNOWN",
	"RATELIMIT_CHECK",
	"FUZZY_WHITE",
	"HFILTER_HELO_NORESOLVE_MX",
	"DBL_BOTNET",
	"REPLYTO_EMAIL_HAS_TITLE",
	"DKIM_MIXED",
	"DBL_ABUSE_PHISH",
	"SUBJECT_ENDS_SPACES",
	"ARC_SIGNED",
	"SORTED_RECIPS",
	"HFILTER_HELO_2",
	"MID_RHS_NOT_FQDN",
	"DKIM_CHECK",
	"RECEIVED_BLOCKLISTDE",
	"KNOWN_MID_CALLBACK",
	"FREEMAIL_FROM",
	"DBL_BLOCKED_OPENRESOLVER",
	"MIME_BAD_UNICODE",
	"RCPT_COUNT_SEVEN",
	"R_RCVD_SPAMBOTS",
	"X_PHP_FORGED_0X",
	"RECEIVED_SPAMHAUS",
	"RCPT_COUNT_ZERO",
	"RCVD_NO_TLS_LAST",
	"DBL_ABUSE_REDIR",
	"INVALID_RCPT_8BIT",
	"SUSPICIOUS_RECIPS",
	"SUSPICIOUS_BOUNDARY3",
	"URI_HIDDEN_PATH",
	"SEM_URIBL_FRESH15",
	"ARC_INVALID",
	"R_DKIM_REJECT",
	"HACKED_WP_PHISHING",
	"BLOCKLISTDE_FAIL",
	"REPLYTO_UNPARSEABLE",
	"MICROSOFT_SPAM",
	"R_DKIM_PERMFAIL",
	"RSPAMD_EMAILBL_FAIL",
	"DWL_DNSWL_BLOCKED",
	"ENVFROM_PRVS",
	"RCVD_TLS_LAST",
	"FORGED_SENDER_VERP_SRS",
	"RWL_MAILSPIKE_POSSIBLE",
	"HFILTER_RCPT_BOUNCEMOREONE",
	"PDF_MANY_OBJECTS",
	"RCVD_IN_DNSWL",
	"FORGED_MSGID_YAHOO",
	"DBL_PHISH",
	"SUBJECT_HAS_QUESTION",
	"HAS_PHPMAILER_SIG",
	"MIME_BASE64_TEXT",
	"BAYES_HAM",
	"RBL_NIXSPAM_FAIL",
	"SEM_URIBL_UNKNOWN",
	"MAIL_RU_MAILER",
	"HEADER_FROM_EMPTY_DELIMITER",
	"ENVFROM_SERVICE_ACCT",
	"RWL_MAILSPIKE_EXCELLENT",
	"RECEIVED_SPAMHAUS_BLOCKED_OPENRESOLVER",
	"CTE_CASE",
	"FORGED_MUA_THEBAT_MSGID",
	"DWL_DNSWL_HI",
	"CHECK_MID",
	"HFILTER_HOSTNAME_5",
	"FORWARDED",
	"RSPAMD_EMAILBL",
	"RBL_SPAMHAUS_DROP",
	"HFILTER_URL_ONELINE",
	"HFILTER_HELO_4",
	"BROKEN_CONTENT_TYPE",
	"ARC_DNSFAIL",
	"RWL_MAILSPIKE_GOOD",
	"HAS_X_PHP_SCRIPT",
	"HFILTER_HOSTNAME_4",
	"R_MIXED_CHARSET_URL",
	"DWL_DNSWL_FAIL",
	"DMARC_POLICY_ALLOW_WITH_FAILURES",
	"DWL_DNSWL",
	"R_SPF_NA",
	"DATA_URI_OBFU",
	"RCVD_DKIM_ARC_DNSWL_MED",
	"PHISHED_GENERIC_SERVICE",
	"RBL_SEM_FAIL",
	"R_SUSPICIOUS_URL",
	"HAS_X_PRIO_ZERO",
	"SPAMHAUS_CHECK",
	"TO_EXCESS_QP",
	"ONCE_RECEIVED_STRICT",
	"HEADER_TO_DELIMITER_TAB",
	"FORGED_OUTLOOK_HTML",
	"FREEMAIL_REPLYTO",
	"R_SPF_NEUTRAL",
	"CHECK_FROM",
	"HAS_ATTACHMENT",
	"RCVD_COUNT_SEVEN",
	"SPAMHAUS_FAIL",
	"FREEMAIL_CC",
	"LOCAL_REDIRECTOR_FALSE",
	"URIBL_MULTI_FAIL",
	"NEURAL_CHECK",
	"URIBL_BLOCKED",
	"TO_NEEDS_ENCODING",
	"PREVIOUSLY_DELIVERED",
	"FROM_HAS_DN",
	"MISSING_MIMEOLE",
	"CHECK_RECEIVED",
	"YANDEX_RU_MAILER",
	"PRECEDENCE_BULK",
	"SUBJ_ALL_CAPS",
	"ONCE_RECEIVED",
	"RDNS_NONE",
	"SIGNED_SMIME",
	"SUSPICIOUS_OPERA_10W_MSGID",
	"RBL_SPAMHAUS_SBL",
	"HTTP_TO_IP",
	"SPECIFIC_CONTENT_CHECK",
	"HFILTER_HOSTNAME_2",
	"HFILTER_FROMHOST_NOT_FQDN",
	"FORGED_MUA_SEAMONKEY_MSGID",
	"REPTO_QUOTE_YAHOO",
	"MIME_TYPES_CALLBACK",
	"MULTIPLE_FROM",
	"SPF_CHECK",
	"BOGUS_ENCRYPTED_AND_TEXT",
	"DMARC_CALLBACK",
	"URI_COUNT_ODD",
	"DBL_ABUSE_BOTNET",
	"HAS_LIST_UNSUB",
	"HEADER_REPLYTO_DELIMITER_TAB",
	"TO_MATCH_ENVRCPT_SOME",
	"RECEIVED_SPAMHAUS_BLOCKED",
	"FAKE_REPLY_C",
	"RCVD_COUNT_TWELVE",
	"TO_DN_SOME",
	"HAS_X_PRIO_THREE",
	"OMOGRAPH_URL",
	"RBL_BLOCKLISTDE",
	"SUBJECT_NEEDS_ENCODING",
	"MID_RHS_MATCH_TO",
	"RBL_SEM_IPV6",
	"RCVD_IN_DNSWL_FAIL",
	"FORGED_MUA_SEAMONKEY_MSGID_UNKNOWN",
	"HAS_X_PRIO",
	"COMPROMISED_ACCT_BULK",
	"FORGED_RECIPIENTS_FORWARDING",
	"WHITELIST_DMARC",
	"HAS_DATA_URI",
	"R_NO_SPACE_IN_FROM",
	"HAS_X_PRIO_TWO",
	"HEADER_TO_EMPTY_DELIMITER",
	"MID_CONTAINS_FROM",
	"MAILLIST",
	"HEADER_FROM_DELIMITER_TAB",
	"FORGED_SENDER_MAILLIST",
	"RECEIVED_SPAMHAUS_SBL",
	"MSBL_EBL_FAIL",
	"RECEIVED_SPAMHAUS_XBL",
	"TO_DOM_EQ_FROM_DOM",
	"LONG_SUBJ",
	"HFILTER_HELO_1",
	"HTML_META_REFRESH_URL",
	"GREYLIST",
	"TO_DN_ALL",
	"R_DKIM_NA",
	"HAS_X_PRIO_ONE",
	"MIME_DOUBLE_BAD_EXTENSION",
	"FROM_EXCESS_QP",
	"R_SPF_DNSFAIL",
	"CC_EXCESS_BASE64",
	"DKIM_TRACE",
	"DWL_DNSWL_LOW",
	"SPOOF_REPLYTO",
	"ARC_NA",
	"RSPAMD_URIBL",
	"RWL_MAILSPIKE_VERYGOOD",
	"CTYPE_MISSING_DISPOSITION",
	"ARC_REJECT",
	"SUBJECT_ENDS_EXCLAIM",
	"R_BAD_CTE_7BIT",
	"NEURAL_LEARN",
	"FREEMAIL_ENVFROM",
	"ZERO_WIDTH_SPACE_URL",
	"WWW_DOT_DOMAIN",
	"X_PHP_EVAL",
	"DMARC_POLICY_SOFTFAIL",
	"RCPT_COUNT_TWO",
	"ARC_CALLBACK",
	"BLACKLIST_SPF_DKIM",
	"RBL_SENDERSCORE_FAIL",
	"MIME_TRACE",
	"DBL",
	"ENVFROM_VERP",
	"REPLIES_CHECK"
}

local parser = argparse()
    :name "rspamadm model test"
    :description "Estimate neural network model's accuracy"
    :help_description_margin(37)
parser:option "-s --spamdir"
      :description "Path to spam emails directory"
      :argname("<dir>")
parser:option "-h --hamdir"
      :description "Path to ham emails directory"
      :argname("<dir>")
parser:option "-n --conns"
      :description "Number of parallel connections"
      :argname("<N>")
      :convert(tonumber)
      :default(10)

-- TODO load from neural.lua
local function create_ann(n, nlayers)
  local nhidden = math.floor(n)
  local t = rspamd_kann.layer.input(n)
  t = rspamd_kann.transform.relu(t)
  -- t = rspamd_kann.transform.sigm(rspamd_kann.layer.dense(t, nhidden));
  t = rspamd_kann.layer.dense(t, nhidden)
  t = rspamd_kann.layer.cost(t, 1, rspamd_kann.cost.ceb_neg)
  return rspamd_kann.new.kann(t)
end

local function train(ann, inputs, outputs)
	local iters = 500
	local niter = ann:train1(inputs, outputs, {
		lr = 0.01,
		max_epoch = iters,
		mini_size = 1,
	})
end

local function predict(ann, input)

	return ann:apply1(input)[1]

end

local function calculate_precision(tp, fp)
	return tp / (tp + fp)
end

local function calculate_recall(tp, fn)
	return tp / (tp + fn)
end

local function fscore(precision, recall)
	return 2 * precision * recall / (precision + recall)
end

local function test(ann, inputs, true_outputs)

	local fp = 0
	local fn = 0
	local tp = 0
	local tn = 0

	local statistics = {}

	for i,inp in ipairs(inputs) do
		local res = predict(ann, inp)
		if true_outputs[i][1] == SPAM_LABEL then
			if res > 0 then
				tp = tp + 1
			else
				fn = fn + 1
			end
		else 
			if res < 0 then
				tn = tn + 1
			else
				fp = fp + 1
			end
		end
	end

	statistics.fp = fp
	statistics.fn = fn
	statistics.tp = tp
	statistics.tn = tn

	statistics.precision = calculate_precision(tp, fp)
	statistics.recall = calculate_recall(tp, fn)
	statistics.fscore = fscore(statistics.precision, statistics.recall)

	statistics.total_spams = tp + fn
	statistics.total_hams = tn + fp

	statistics.total_emails = tp + fp + tn + fn

	return statistics
end

-- TODO try to reuse corpus_test
local function scan_emails(n_parallel, path, timeout)

  local rspamc_command = string.format("%s --connect %s -j --compact -n %s -t %.3f %s",
      "rspamc", 'localhost:11334', n_parallel, timeout, path)
  local result = assert(io.popen(rspamc_command))
  result = result:read("*all")
  return result
end

-- TODO try to reuse corpus_test
local function encoded_json_to_symbols_table(result)
  -- Returns table containing score, action, list of symbols

  local symbols = {}
  local ucl_parser = ucl.parser()

  local is_good, err = ucl_parser:parse_string(result)

  if not is_good then
    rspamd_logger.errx("Parser error: %1", err)
    return nil
  end

  result = ucl_parser:get_object()

  for sym, _ in pairs(result.symbols) do
    symbols[sym] = true
  end

  return symbols
end


local function filter_scan_results(results, actual_email_type)

  local dataset = {}

  results = lua_util.rspamd_str_split(results, "\n")

  if results[#results] == "" then
    results[#results] = nil
  end

  for _, result in pairs(results) do
  	local data = {}
  	data.email_type = actual_email_type
  	data.symbols = encoded_json_to_symbols_table(result)
  	table.insert(dataset, data)
  end

  return dataset
end

local function onehotencode_dataset(dataset, all_symbols)

	local X = {}
	local Y = {}

	for _, data_row in pairs(dataset) do 

		x = {}
		for _, sym in pairs(all_symbols) do
			if data_row.symbols[sym] == true then
				table.insert(x, 1)
			else
				table.insert(x, 0)
			end
		end

		table.insert(X, x)

		if (data_row.email_type == "HAM") then
			table.insert(Y, {HAM_LABEL})
		else
			table.insert(Y, {SPAM_LABEL})
		end
	end

	return X, Y
end

local function concat_tables(table1, table2) 

	concated_table = {}

	for i = 1, #table1 do
		concated_table[#concated_table + 1] = table1[i]
	end

	for i = 1, #table2 do
		concated_table[#concated_table + 1] = table2[i]
	end

	return concated_table
end

local function split_dataset(X, Y, split_ratio)

	if split_ratio > 1 then
		rspamd_logger.errx("Split ratio cannot be greater than 1")
		return nil
	end

	local split_idx = split_ratio * #X

	X_train = {}
	X_test = {}

	Y_train = {}
	Y_test = {}

	for i = 1,#X do

		if i < split_idx then
			X_train[#X_train + 1] = X[i]
			Y_train[#Y_train + 1] = Y[i]
		else 
			X_test[#X_test + 1] = X[i]
			Y_test[#Y_test + 1] = Y[i]
		end
	end

	return X_train, Y_train, X_test, Y_test
end	

local function shuffle_dataset(X, Y)

	for i = #X, 2, -1 do
		local j = math.random(i)
		X[i], X[j] = X[j], X[i]
    	Y[i], Y[j] = Y[j], Y[i]
	end

end

local function scan_emails_and_prepare_dataset(ham_directory, spam_directory, n_connections)
	rspamd_logger.infox("Scanning spam emails")
	results = scan_emails(n_connections, spam_directory, 10)
	local dataset = filter_scan_results(results, "SPAM")	
	X_spam, Y_spam = onehotencode_dataset(dataset, all_symbols)

	rspamd_logger.infox("Scanning ham emails")
	results = scan_emails(n_connections, ham_directory, 10)
	dataset = filter_scan_results(results, "HAM")	
	X_ham, Y_ham = onehotencode_dataset(dataset, all_symbols)

	local X = concat_tables(X_ham, X_spam)
	local Y = concat_tables(Y_ham, Y_spam)

	return X, Y
end

local function print_statistics(stats)
	rspamd_logger.messagex("Total test examples: %s", stats.total_emails)
	rspamd_logger.messagex("F-score: %s", stats.fscore)
	rspamd_logger.messagex("Precision: %s", stats.precision)
	rspamd_logger.messagex("Recall: %s", stats.recall)
	rspamd_logger.messagex("Total ham emails incorrectly flagged as spam: %s / %s", stats.fp, stats.total_hams)	
	rspamd_logger.messagex("Total spam emails incorrectly flagged as ham: %s / %s", stats.fn, stats.total_spams)
	rspamd_logger.messagex("Total hams emails correctly classified: %s / %s", stats.tn, stats.total_hams)	
	rspamd_logger.messagex("Total spam emails correctly classified: %s / %s", stats.tp, stats.total_spams)
end	

local function load_all_symbols()

	-- TODO make it a command line option
	local config_path = rspamd_paths["CONFDIR"] .. "/" .. "rspamd.conf"
	
	local _r,err = rspamd_config:load_ucl(config_path)
	if not _r then
		rspamd_logger.errx('cannot parse %s: %s', config_path, err)
		os.exit(1)
	end

	_r,err = rspamd_config:parse_rcl({'logging', 'worker'})
	if not _r then
		rspamd_logger.errx('cannot process %s: %s', opts['config'], err)
		os.exit(1)
	end

	-- local symbols = rspamd_config:get_symbols()
	local symbols =	lua_settings.all_symbols()
	local count = 0

	for k, v in pairs(symbols) do
		table.insert(all_symbols, k)
		count = count + 1
	end

	rspamd_logger.messagex("loaded %s symbols", count)

	return all_symbols
end

local function handler(args)
	opts = parser:parse(args)

	-- load_all_symbols()

	local ham_directory = opts['hamdir']
	local spam_directory = opts['spamdir']
	local n_connections = opts['conns']

	local X, Y = scan_emails_and_prepare_dataset(ham_directory, spam_directory, n_connections)

	shuffle_dataset(X, Y)

	local X_train, Y_train, X_test, Y_test = split_dataset(X, Y, 0.7)
	rspamd_logger.messagex("Number of training examples: %s", #X_train)
	rspamd_logger.messagex("Number of testing examples: %s", #X_test)

	local ann = create_ann(#all_symbols, 1)

	rspamd_logger.infox("Training ANN")
	train(ann, X_train, Y_train)

	rspamd_logger.infox("Testing ANN")
	local test_statistics = test(ann, X_test, Y_test)

	print_statistics(test_statistics)

end

return {
  handler = handler,
  description = parser._description,
  name = 'modeltest'
}

