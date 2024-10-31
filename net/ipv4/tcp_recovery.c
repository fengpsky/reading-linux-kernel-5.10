// SPDX-License-Identifier: GPL-2.0
#include <linux/tcp.h>
#include <net/tcp.h>

static bool tcp_rack_sent_after(u64 t1, u64 t2, u32 seq1, u32 seq2)
{
	return t1 > t2 || (t1 == t2 && after(seq1, seq2));
}

static u32 tcp_rack_reo_wnd(const struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (!tp->reord_seen) {
		/* If reordering has not been observed, be aggressive during
		 * the recovery or starting the recovery by DUPACK threshold.
		 */
		if (inet_csk(sk)->icsk_ca_state >= TCP_CA_Recovery)
			return 0;

		if (tp->sacked_out >= tp->reordering &&
		    !(sock_net(sk)->ipv4.sysctl_tcp_recovery & TCP_RACK_NO_DUPTHRESH))
			return 0;
	}

	/* To be more reordering resilient, allow min_rtt/4 settling delay.
	 * Use min_rtt instead of the smoothed RTT because reordering is
	 * often a path property and less related to queuing or delayed ACKs.
	 * Upon receiving DSACKs, linearly increase the window up to the
	 * smoothed RTT.
	 */
	return min((tcp_min_rtt(tp) >> 2) * tp->rack.reo_wnd_steps,
		   tp->srtt_us >> 3);
}

s32 tcp_rack_skb_timeout(struct tcp_sock *tp, struct sk_buff *skb, u32 reo_wnd)
{
	/*前报文的发送时间戳+最近测量的RTT+乱序窗口时长，小于当前接收TCP时间，即认为此报文已经丢失
			*//*小于等于零，可以判断为丢包，大于零，为需要在额外等待的时间*/
	return tp->rack.rtt_us + reo_wnd -
	       tcp_stamp_us_delta(tp->tcp_mstamp, tcp_skb_timestamp_us(skb));
}

/* RACK loss detection (IETF draft draft-ietf-tcpm-rack-01):
 *
 * Marks a packet lost, if some packet sent later has been (s)acked.
 * The underlying idea is similar to the traditional dupthresh and FACK
 * but they look at different metrics:
 *
 * dupthresh: 3 OOO packets delivered (packet count)
 * FACK: sequence delta to highest sacked sequence (sequence space)
 * RACK: sent time delta to the latest delivered packet (time domain)
 *
 * The advantage of RACK is it applies to both original and retransmitted
 * packet and therefore is robust against tail losses. Another advantage
 * is being more resilient to reordering by simply allowing some
 * "settling delay", instead of tweaking the dupthresh.
 *
 * When tcp_rack_detect_loss() detects some packets are lost and we
 * are not already in the CA_Recovery state, either tcp_rack_reo_timeout()
 * or tcp_time_to_recover()'s "Trick#1: the loss is proven" code path will
 * make us enter the CA_Recovery state.
 函数tcp_rack_detect_loss负责依据RACK算法标记丢失报文，
 即如果发送时间靠后的报文已经被确认（ACK或者SACK），那么之前的未确认报文认为已经丢失。
 为抵御乱序的情况，RACK在确认报文和丢失报文之间设置了一定的时间差值。遍历tsorted时间排序的报文链表，
 从最早发送的报文开始，如果其已经被标记为丢失，但是还没有重传，不进行处理。
 如果报文剩余时间小于等于0，表明已经超时，由函数tcp_mark_skb_lost进行标记，
 否则，如果报文剩余时间大于0，计算超时时长，返回给调用函数设置定时器。
 */
static void tcp_rack_detect_loss(struct sock *sk, u32 *reo_timeout)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct sk_buff *skb, *n;
	u32 reo_wnd;

	*reo_timeout = 0;
	reo_wnd = tcp_rack_reo_wnd(sk);/*获取乱序时间窗口值*/
	list_for_each_entry_safe(skb, n, &tp->tsorted_sent_queue,
				 tcp_tsorted_anchor) {
		struct tcp_skb_cb *scb = TCP_SKB_CB(skb);
		s32 remaining;

		/* Skip ones marked lost but not yet retransmitted */
		if ((scb->sacked & TCPCB_LOST) &&
		    !(scb->sacked & TCPCB_SACKED_RETRANS))
			continue;/*忽略已经标记丢失但未重传的skb*/
		
			 /*已经判断完最近被(s)ack确认skb的之前所有的包
			也就是 tp->rack.mstamp    <before tcp_skb_timestamp_us(skb)  
			认为数据包已经标记完*/
		if (!tcp_rack_sent_after(tp->rack.mstamp,
					 tcp_skb_timestamp_us(skb),
					 tp->rack.end_seq, scb->end_seq))
			break;

		/* A packet is lost if it has not been s/acked beyond
		 * the recent RTT plus the reordering window.
		 前报文的发送时间戳+最近测量的RTT+乱序窗口时长，小于当前接收TCP时间，即认为此报文已经丢失
         *//*小于等于零，可以判断为丢包，大于零，为需要在额外等待的时间*/
		remaining = tcp_rack_skb_timeout(tp, skb, reo_wnd);
		if (remaining <= 0) {
			tcp_mark_skb_lost(sk, skb);
			list_del_init(&skb->tcp_tsorted_anchor);
		} else {
			/* Record maximum wait time *//*记录需要等待最长的额外时间，用该值重置REO定时器*/
			*reo_timeout = max_t(u32, *reo_timeout, remaining);
		}
	}
}

/*
RACK基本思想：如果发送端收到的确认包中的SACK选项确认收到了一个数据包，
那么在这个数据包之前发送的数据包要么是在传输过程中发生了乱序，要么是发生了丢包。
RACK并不记录数据被(s)ACK的时间，而是在收到ACK的时候，记录被该ACK确认的数据包的发送时间，
在这些发送时间中取Recent，即最晚发送的。RACK的思想是，记录这个Recent (s)ACK所确认数据包的发送时间T.rack，
然后给定一个时间窗口reo_wnd，在时间T.rack-reo_wnd之前发送的未被确认的数据包均被标记为LOST，
然后这些数据包会被交给发送逻辑去发送。这非常符合常理。
　　RACK可以修复丢包而不用等一个比较长的RTO超时，RACK可以用于快速恢复也可以用于超时恢复，
既可以利用初传的数据包探测丢包也可以利用重传的数据包探测丢包，而且可以探测初传丢包也可以探测重传丢包，
因此RACK是一个适应多种场景的丢包恢复机制。

*/
void tcp_rack_mark_lost(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout;

	if (!tp->rack.advanced)
		return;

	/* Reset the advanced flag to avoid unnecessary queue scanning */
	tp->rack.advanced = 0;
//由子函数tcp_rack_detect_loss标记丢失报文，并且设置重传队列中报文超时的定时器ICSK_TIME_REO_TIMEOUT。
	tcp_rack_detect_loss(sk, &timeout);
	if (timeout) {
		timeout = usecs_to_jiffies(timeout) + TCP_TIMEOUT_MIN;
		inet_csk_reset_xmit_timer(sk, ICSK_TIME_REO_TIMEOUT,
					  timeout, inet_csk(sk)->icsk_rto);
	}
}

/* Record the most recently (re)sent time among the (s)acked packets
 * This is "Step 3: Advance RACK.xmit_time and update RACK.RTT" from
 * draft-cheng-tcpm-rack-00.txt
 */
void tcp_rack_advance(struct tcp_sock *tp, u8 sacked, u32 end_seq,
		      u64 xmit_time)
{
	u32 rtt_us;

	rtt_us = tcp_stamp_us_delta(tp->tcp_mstamp, xmit_time);
	if (rtt_us < tcp_min_rtt(tp) && (sacked & TCPCB_RETRANS)) {
		/* If the sacked packet was retransmitted, it's ambiguous
		 * whether the retransmission or the original (or the prior
		 * retransmission) was sacked.
		 *
		 * If the original is lost, there is no ambiguity. Otherwise
		 * we assume the original can be delayed up to aRTT + min_rtt.
		 * the aRTT term is bounded by the fast recovery or timeout,
		 * so it's at least one RTT (i.e., retransmission is at least
		 * an RTT later).
		 */
		return;
	}
	tp->rack.advanced = 1;
	tp->rack.rtt_us = rtt_us;
	if (tcp_rack_sent_after(xmit_time, tp->rack.mstamp,
				end_seq, tp->rack.end_seq)) {
		tp->rack.mstamp = xmit_time;
		tp->rack.end_seq = end_seq;
	}
}

/* We have waited long enough to accommodate reordering. Mark the expired
 * packets lost and retransmit them.
 */
void tcp_rack_reo_timeout(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	u32 timeout, prior_inflight;

	prior_inflight = tcp_packets_in_flight(tp);
	tcp_rack_detect_loss(sk, &timeout);
	if (prior_inflight != tcp_packets_in_flight(tp)) {
		if (inet_csk(sk)->icsk_ca_state != TCP_CA_Recovery) {
			tcp_enter_recovery(sk, false);
			if (!inet_csk(sk)->icsk_ca_ops->cong_control)
				tcp_cwnd_reduction(sk, 1, 0);
		}
		tcp_xmit_retransmit_queue(sk);
	}
	if (inet_csk(sk)->icsk_pending != ICSK_TIME_RETRANS)
		tcp_rearm_rto(sk);
}

/* Updates the RACK's reo_wnd based on DSACK and no. of recoveries.
 *
 * If DSACK is received, increment reo_wnd by min_rtt/4 (upper bounded
 * by srtt), since there is possibility that spurious retransmission was
 * due to reordering delay longer than reo_wnd.
 *
 * Persist the current reo_wnd value for TCP_RACK_RECOVERY_THRESH (16)
 * no. of successful recoveries (accounts for full DSACK-based loss
 * recovery undo). After that, reset it to default (min_rtt/4).
 *
 * At max, reo_wnd is incremented only once per rtt. So that the new
 * DSACK on which we are reacting, is due to the spurious retx (approx)
 * after the reo_wnd has been updated last time.
 *
 * reo_wnd is tracked in terms of steps (of min_rtt/4), rather than
 * absolute value to account for change in rtt.
 */
void tcp_rack_update_reo_wnd(struct sock *sk, struct rate_sample *rs)
{
	struct tcp_sock *tp = tcp_sk(sk);

	if (sock_net(sk)->ipv4.sysctl_tcp_recovery & TCP_RACK_STATIC_REO_WND ||
	    !rs->prior_delivered)
		return;

	/* Disregard DSACK if a rtt has not passed since we adjusted reo_wnd */
	if (before(rs->prior_delivered, tp->rack.last_delivered))
		tp->rack.dsack_seen = 0;

	/* Adjust the reo_wnd if update is pending */
	if (tp->rack.dsack_seen) {
		tp->rack.reo_wnd_steps = min_t(u32, 0xFF,
					       tp->rack.reo_wnd_steps + 1);
		tp->rack.dsack_seen = 0;
		tp->rack.last_delivered = tp->delivered;
		tp->rack.reo_wnd_persist = TCP_RACK_RECOVERY_THRESH;
	} else if (!tp->rack.reo_wnd_persist) {
		tp->rack.reo_wnd_steps = 1;
	}
}

/* RFC6582 NewReno recovery for non-SACK connection. It simply retransmits
 * the next unacked packet upon receiving
 * a) three or more DUPACKs to start the fast recovery
 * b) an ACK acknowledging new data during the fast recovery.
 */
void tcp_newreno_mark_lost(struct sock *sk, bool snd_una_advanced)
{
	const u8 state = inet_csk(sk)->icsk_ca_state;
	struct tcp_sock *tp = tcp_sk(sk);
	/*当拥塞状态小于TCP_CA_Recovery，并且SACK（对于Reno，sacked_out等于dupack数量）
	确认的报文数量大于等于乱序级别时，认为发生了丢包，
	由于无法确认丢包数量，这里认为数量为1*/
	/*如果状态为recover 状态，且同时ack 推动了snd_una 即flag_data_acked；
	//也就是在确实发生报文丢失状态下, ack报文触发了 flag_data_acked；*/
	if ((state < TCP_CA_Recovery && tp->sacked_out >= tp->reordering) ||
	    (state == TCP_CA_Recovery && snd_una_advanced)) {
		struct sk_buff *skb = tcp_rtx_queue_head(sk);
		u32 mss;

		if (TCP_SKB_CB(skb)->sacked & TCPCB_LOST)
			return;

		mss = tcp_skb_mss(skb);
		//如果重传队列首报文长度大于MSS，执行分片处理，仅标记一个长度为MSS的报文为丢失状态
		if (tcp_skb_pcount(skb) > 1 && skb->len > mss)
			tcp_fragment(sk, TCP_FRAG_IN_RTX_QUEUE, skb,
				     mss, mss, GFP_ATOMIC);

		tcp_mark_skb_lost(sk, skb);
	}
}
