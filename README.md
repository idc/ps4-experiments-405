Code for random experiments. May or may not work.

**Run at your own risk.**

* fuse_loader - Applies some patches and initializes [FUSE](https://en.wikipedia.org/wiki/Filesystem_in_Userspace) so it can be used on retail PS4s. Normally only available on devkit or testkit.
* hostapp_launch - Launches an application (game, app, etc) from /hostapp, needs to have been prior mounted somehow (perhaps nullfs)? Normally only available on devkit or testkit.
* hostapp_launch_patcher - Patches SceShellCore to allow hostapp_launch to work.
