package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"dns-over-smtp/internal/guard"
	"dns-over-smtp/internal/protocol"
	"github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
	"github.com/miekg/dns"
)

type inbox struct {
	client   *imapclient.Client
	conn     net.Conn
	stop     func() bool
	firstUID uint32
}

func (c *Client) openInbox(ctx context.Context) (*inbox, error) {
	addr := net.JoinHostPort(c.config.IMAPHost, fmt.Sprint(c.config.IMAPPort))
	d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 10 * time.Second}, Config: &tls.Config{ServerName: c.config.IMAPHost, MinVersion: tls.VersionTLS12, RootCAs: c.config.TLSRootCAs}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connect IMAP: %w", err)
	}
	box := &inbox{conn: conn}
	box.stop = context.AfterFunc(ctx, func() { conn.Close() })
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		box.close()
		return nil, err
	}
	ic, err := imapclient.New(conn)
	if err != nil {
		box.close()
		return nil, err
	}
	box.client = ic
	ic.ErrorLog = guard.EventLogger{Event: "imap_session_error"}
	ic.Timeout = 10 * time.Second
	if err := ic.Login(c.config.IMAPUser, c.config.IMAPPass); err != nil {
		box.close()
		return nil, errors.New("IMAP login failed")
	}
	status, err := ic.Select(c.config.IMAPMailbox, true)
	if err != nil {
		box.close()
		return nil, errors.New("cannot select IMAP mailbox")
	}
	if status.UidNext == 0 {
		box.close()
		return nil, errors.New("IMAP server did not provide UIDNEXT")
	}
	box.firstUID = status.UidNext
	return box, nil
}

func (b *inbox) close() {
	if b.stop != nil {
		b.stop()
	}
	if b.conn != nil {
		b.conn.Close()
	}
}

func (b *inbox) wait(ctx context.Context, id string, interval time.Duration) (*dns.Msg, error) {
	seen := make(map[uint32]bool)
	for {
		if ctx.Err() != nil {
			return nil, errors.New("timed out waiting for DNS bounce")
		}
		criteria := imap.NewSearchCriteria()
		criteria.Uid = new(imap.SeqSet)
		criteria.Uid.AddRange(b.firstUID, 0)
		criteria.Body = []string{id}
		uids, err := b.client.UidSearch(criteria)
		if err != nil {
			return nil, fmt.Errorf("search IMAP bounce: %w", err)
		}
		if len(uids) > 128 {
			return nil, errors.New("too many matching inbox messages")
		}
		for _, uid := range uids {
			// n:* also matches the last UID when n exceeds the current maximum.
			if uid < b.firstUID || seen[uid] {
				continue
			}
			seen[uid] = true
			set := new(imap.SeqSet)
			set.AddNum(uid)
			section := &imap.BodySectionName{Peek: true, Partial: []int{0, protocol.MaxMailBytes + 1}}
			messages := make(chan *imap.Message, 1)
			if err := b.client.UidFetch(set, []imap.FetchItem{section.FetchItem()}, messages); err != nil {
				return nil, err
			}
			for message := range messages {
				body := message.GetBody(section)
				if body == nil {
					continue
				}
				raw, err := io.ReadAll(io.LimitReader(body, protocol.MaxMailBytes+1))
				if err != nil {
					return nil, err
				}
				answer, err := protocol.ParseBounce(raw, id)
				if err == nil {
					return answer, nil
				}
				// Other email containing the ID is not a response; keep waiting.
			}
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, errors.New("timed out waiting for DNS bounce")
		case <-timer.C:
		}
	}
}
