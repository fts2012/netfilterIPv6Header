//hello world
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

// static
static int __init hello_init(void)
{
	printk("<1>Hello World module init\n");
	return 0;
}


static void __exit hello_exit(void)
{
	printk("<1>Hello World module exit\n");
}

/*module initial and exit*/
module_init(hello_init);
module_exit(hello_exit);

/*module informations*/
MODULE_AUTHOR("Qiu Jin");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hello Demo");
