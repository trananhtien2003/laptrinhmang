#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/string.h>

static struct nf_hook_ops *nf_hook_ex_ops = NULL;

static unsigned int nf_hook_ex(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *iph;
	if(!skb)
		return NF_ACCEPT;
	iph = ip_hdr(skb);
	if (iph->protocol == 1) {
		printk(KERN_INFO "Droped received packet \n");
		return NF_DROP;
	}
	return NF_ACCEPT;
}

/* Được gọi khi sử dụng lệnh 'insmod' */
static int __init kmod_init(void) {
	nf_hook_ex_ops = (struct nf_hook_ops*)kcalloc(1,  sizeof(struct nf_hook_ops), GFP_KERNEL);
	if (nf_hook_ex_ops != NULL) {

		/* đây là hàm callback `nf_hook_ex` kiểu nf_hookfn - định nghĩa trong include/linux/netfilter.h, line 47
				- các tham số của hook mà người dùng định nghĩa phải khớp với kiểu nf_hookfn */
		nf_hook_ex_ops->hook = (nf_hookfn*)nf_hook_ex;
		
		/* Sự kiện mà hook này đăng ký  */
		nf_hook_ex_ops->hooknum = NF_INET_PRE_ROUTING; 

		/* Chỉ xử lý các Internet (IPv4) packet  */
		nf_hook_ex_ops->pf = NFPROTO_IPV4;

		/* Cài đặt độ ưu tiên của hook này ở mức độ cao nhất*/
		nf_hook_ex_ops->priority = NF_IP_PRI_FIRST;
		
		nf_register_net_hook(&init_net, nf_hook_ex_ops);
	}
	return 0;
}


static void __exit kmod_exit(void) {
	if(nf_hook_ex_ops != NULL) {
		nf_unregister_net_hook(&init_net, nf_hook_ex_ops);
		kfree(nf_hook_ex_ops);
	}
	printk(KERN_INFO "Exit");
}

module_init(kmod_init);
module_exit(kmod_exit);

MODULE_LICENSE("GPL");
