#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum, struct sk_buff **skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    printk(KERN_INFO "packet detected\n");
    return NF_ACCEPT;
}

int init_module()
{
    printk("SWS: init_module()");
    nfho.hook = hook_func;                       //function to call when conditions below met
    nfho.hooknum = NF_INET_PRE_ROUTING;            //called right after packet recieved, first hook in Netfilter
    nfho.pf = PF_INET;                           //IPV4 packets
    nfho.priority = NF_IP_PRI_FIRST;             //set to highest priority over all other hook functions
    nf_register_hook(&nfho);                     //register hook

    return 0;
}

void cleanup_module()
{
    nf_unregister_hook(&nfho);
    printk("SWS: cleanup_module()");
}
