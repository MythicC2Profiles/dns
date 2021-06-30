from mythic_c2_container.C2ProfileBase import *


class DNS(C2Profile):
    name = "dns"
    description = "Uses DNS TXT Queries to establish communication with the DNS Server."
    author = "@thiagomayllart"
    is_p2p = False
    is_server_routed = False
    parameters = [
        C2ProfileParameter(
            name="callback_domains",
            description="Callback Domains (Separated by ,)",
            default_value="eg.example.com",
            required=True,
        ),
        C2ProfileParameter(
            name="killdate",
            description="Kill Date",
            parameter_type=ParameterType.Date,
            default_value=365,
            required=False,
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform Key Exchange",
            choices=["T", "F"],
            parameter_type=ParameterType.ChooseOne,
        ),
        C2ProfileParameter(
            name="callback_jitter",
            description="Callback Jitter in percent",
            default_value="23",
            verifier_regex="^[0-9]+$",
            required=False,
        ),
        C2ProfileParameter(
            name="domain_front",
            description="Host header value for domain fronting",
            default_value="",
            required=False,
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Crypto type",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            required=False,
            crypto_type=True
        ),
        C2ProfileParameter(
            name="msginit",
            description="Subdomain prefix for connection initialization (should be the same as the one in the profile instance)",
            default_value="app",
            required=True,
        ),
        C2ProfileParameter(
            name="msgdefault",
            description="Subdomain prefix for default messages (should be the same as the one in the profile instance)",
            default_value="dash",
            required=True,
        ),
        C2ProfileParameter(
            name="callback_interval",
            description="Callback Interval in seconds",
            default_value="10",
            verifier_regex="^[0-9]+$",
            required=False,
        ),
        C2ProfileParameter(
            name="hmac_key",
            description="Key to verify signature of DNS queries (avoids tampering of packets in agent channel). Should be the same as the one in the profile instance ",
            default_value="hmac secret key",
            required=True,
        ),
    ]
