#include <sys/modctl.h>
#include <sys/cmn_err.h>

/*
 * Module linkage information for the kernel.
 */
static struct modlmisc modlmisc = {
	&mod_miscops, "load module"
};

static struct modlmisc modlmisc1 = {
	&mod_miscops, "unload module"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};

static struct modlinkage modlinkage1 = {
	MODREV_1, (void *)&modlmisc1, NULL
};


int
_init(void)
{
	cmn_err(CE_NOTE, "loading foomod");
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	cmn_err(CE_NOTE, "unloading foomod");
	return (mod_remove(&modlinkage1));
}

int
_info(struct modinfo *modinfop)
{
	cmn_err(CE_NOTE, "hello kernel");
	return (mod_info(&modlinkage, modinfop));
}
