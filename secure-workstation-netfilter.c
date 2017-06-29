#include <linux/delay.h>
#include <linux/hashtable.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/spinlock.h>
#include <linux/sysfs.h>
#include <linux/types.h>

MODULE_LICENSE("GPL");

struct sws_rule {
    __u32   srcip;
    __u32   dstip;
    bool    allow;
    struct list_head list;
};
static LIST_HEAD(rules_list);

struct prompt_item {
    __u32   srcip;
    __u32   dstip;
    struct list_head list;
};
static LIST_HEAD(prompts_list);
static DEFINE_SPINLOCK(prompts_list_lock);

static struct nf_hook_ops nfho;

unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *)) {
    struct sws_rule *rule;
    struct iphdr *ip_header;
    long i;

    if (!skb)
        return NF_DROP;
    ip_header = (struct iphdr *) skb_network_header(skb);
    printk("src: %x, dst: %x", ip_header->saddr, ip_header->daddr);
    if ((ip_header->saddr & 0xFFFFFF) != 0x02890a) {
        printk(" accepted\n");
        return NF_ACCEPT;
    }
    list_for_each_entry(rule, &rules_list, list) {
        if (rule->srcip == ip_header->saddr &&
            rule->dstip == ip_header->daddr) {
            printk(" matched\n");
            return rule->allow ? NF_ACCEPT : NF_DROP;
        }
    }

    struct prompt_item *new_prompt;
    new_prompt = kmalloc(sizeof(*new_prompt), GFP_KERNEL);
    new_prompt->srcip = ip_header->saddr;
    new_prompt->dstip = ip_header->daddr;
    INIT_LIST_HEAD(&new_prompt->list);
    spin_lock(&prompts_list_lock);
    list_add_tail(&new_prompt->list, &prompts_list);
    spin_unlock(&prompts_list_lock);
    printk(" dropped\n");
    return NF_DROP;
}

static ssize_t sws_prompt_show(struct class *cls,
                               struct class_attribute *attr,
                               char *buf) {
    struct prompt_item *item;
    spin_lock(&prompts_list_lock);
    if (list_empty(&prompts_list)) {
        spin_unlock(&prompts_list_lock);
        return 0;
    }
    item = list_first_entry(&prompts_list, struct prompt_item, list);
    list_del(&item->list);
    spin_unlock(&prompts_list_lock);

    int count = sprintf(buf, "%d %d", item->srcip, item->dstip);
    kfree(item);
    return count;
}

// static ssize_t sws_prompt_store(struct class *cls,
//                                 struct class_attribute *attr,
//                                 const char *buffer, size_t count) {

// }

static ssize_t sws_rules_store(struct class *cls,
                         struct class_attribute *attr,
                         const char *buffer, size_t count) {
    struct sws_rule *rule;

    __u32 srcip, dstip;
    int allow;
    sscanf(buffer, "%d %d %d\n", &srcip, &dstip, &allow);

    rule = kmalloc(sizeof(*rule), GFP_KERNEL);
    if (!rule) {
        printk("rule kmalloc failed");
        return count;
    }
    rule->srcip = srcip;
    rule->dstip = dstip;
    rule->allow = (allow == 1);

    list_add_tail(&rule->list, &rules_list);
    return count;
}

static struct class *sws_class;
static const struct class_attribute sws_rules_attr = {
    .attr = {
        .name = "netfilter_rules",
        .mode = S_IWUSR,
    },
    .store = sws_rules_store,
};
static const struct class_attribute sws_prompt_attr = {
    .attr = {
        .name = "prompt",
        .mode = /*S_IWUSR | */S_IRUGO,
    },
    .show = sws_prompt_show,
    //.store = sws_prompt_store,
};

int sysfs_init() {
    int ret;
    sws_class = class_create(THIS_MODULE, "secure-workstation-netfilter");
    if (IS_ERR(sws_class)) {
        pr_err("Couldn't create sysfs class.\n");
        return PTR_ERR(sws_class);
    }
    ret = class_create_file(sws_class, &sws_rules_attr);
    if (ret) return ret;
    return class_create_file(sws_class, &sws_prompt_attr);
}

int init_module() {
    printk("secure-workstation-netfilter: init_module()");

    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_hook(&nfho);

    return sysfs_init();
}

void cleanup_module() {
    struct sws_rule *rule, *tmp;

    nf_unregister_hook(&nfho);
    class_destroy(sws_class);

    list_for_each_entry_safe(rule, tmp, &rules_list, list) {
        list_del(&rule->list);
        kfree(rule);
    }

    printk("secure-workstation-netfilter: cleanup_module()");
}
