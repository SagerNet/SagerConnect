module github.com/sagernet/sagerconnect

go 1.16

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e
	github.com/miekg/dns v1.1.43
	github.com/pkg/errors v0.9.1
	github.com/ulikunitz/xz v0.5.10
	github.com/xjasonlyu/tun2socks v1.18.4-0.20210813034434-85cf694b8fed
	golang.org/x/sys v0.1.0
)

replace github.com/xjasonlyu/tun2socks v1.18.4-0.20210813034434-85cf694b8fed => github.com/sagernet/tun2socks v1.18.4-0.20210820015834-2ee7f3879e14
