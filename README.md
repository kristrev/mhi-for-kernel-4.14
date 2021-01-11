# Kernel 4.14 MHI backport

This repo contains backports of the drivers for the MHI bus, the client interface driver (from now on referred to as
UCI) and the network driver. MHI is required driver for (among others) for using  SDX55-based modems (like Quectel
RM500Q or Telit FN980) together with PCI. Please note that the steps for enable PCI between each modem, and that you
hardware (m.2 slot) has to support PCI (often in addition to USB).

Because not all parts of MHI is upstream yet, the code in this repo is gathered from different locations. The changes
contained here are:

* All MHI bus changes from the `mhi-next` repo (per 08/01/2021).
* Version 18 of the "userspace MHI client interface driver" patch series.
* `mhi\_net.c` (the network interface driver) from `net-next` (per 08/01/2021).

The repo is structured as follows:
* `drivers/bus/mhi`: Contains the code (backported) for the MHI bus and UCI.
* `drivers/net`: Contains the network interface driver.
* `include/linux`: MHI header file.
* `patches/`: Contains two patches, one for the MHI bus + UCI and another for the network driver. Applies cleanly and
  builds fine with kernel 4.14.212.

I will try to keep this repo reasonably up to date, but PRs are more than welcome. The drivers are tested and works fine
on kernel 4.14.212. I used the Quectel RM500Q modem, and was able to communicate with the module and establish a data
connection (using `qmicli`) + send and receive data.

## List of changes

The backport is made up of the following changes: 

Bus + UCI:
- Copied `include/linux/mhi.h` from `mhi-next`.
- Copied the entire `drivers/bus/mhi` folder.
- Added the following to the bottom of `drivers/bus/Kconfig`: source "drivers/bus/mhi/Kconfig"
- Added the following to the bottom of `drivers/bus/Makefile`: obj-$(CONFIG_MHI_BUS)		+= mhi/
- Updated `include/linux/mod_devicetable.h` with the constant and the device id struct.
- Replaced `ida_alloc/ida_free` with `ida_simple_get/ida_simple_remove`.
- Updated `drivers/bus/mhi/uci.c`. Changed mhi_uci_poll() to return unsigned, changed mask to unsigned int and then removed the E in front of events (like EPOLLOUT).
- Added `PCI_VENDOR_ID_QCOM` (0x17cb) to `include/linux/pci_ids.h`.

Net:
- Copied `drivers/net/mhi_net.c`
- Updated `drivers/net/{Kconfig,Makefile}` with the entry/symbol for `mhi_net` (copied changes from `net-next`).
- Change stats from `u64_stats_t` to `u64`, `u64_stats_t` does not exist in 4.14.
- The different `u64_stats_...()` helper functions does not exist in 4.14, so the code for the updating the different
  counters had to be changed.

## Compiling for OpenWRT

In order to compile the drivers for OpenWRT, you need to copy the two patches to one of folders used for patches inside
`target/linux/generic` (for example `backport-4.14`). You probably want to give the patches another name (or at least
another numbered prefix) to have them fit in with the other patches. In addition, you need to add `menuconfig` entries
for the two drivers. I added the following to `package/kernel/linux/modules/other.mk` (for bus + UCI):

```
define KernelPackage/mhi-bus
  SUBMENU:=$(OTHER_MENU)
  TITLE:=MHI bus
  KCONFIG:=CONFIG_MHI_BUS \
           CONFIG_MHI_BUS_PCI_GENERIC \
           CONFIG_MHI_UCI \
           CONFIG_MHI_BUS_DEBUG=y
  FILES:=$(LINUX_DIR)/drivers/bus/mhi/mhi_pci_generic.ko \
         $(LINUX_DIR)/drivers/bus/mhi/mhi_uci.ko \
         $(LINUX_DIR)/drivers/bus/mhi/core/mhi.ko
  AUTOLOAD:=$(call AutoProbe,mhi mhi_pci_generic mhi_uci)
endef

define KernelPackage/mhi-bus/description
  Kernel modules for the Qualcoom MHI bus.
endef

$(eval $(call KernelPackage,mhi-bus))
```

And the following to `package/kernel/linux/modules/netdevices.mk` (for the network device):

```
define KernelPackage/mhi-net
  SUBMENU:=$(NETWORK_DEVICES_MENU)
  TITLE:=MHI Network Device
  DEPENDS:=@PCI_SUPPORT +kmod-mhi-bus
  KCONFIG:=CONFIG_MHI_NET
  FILES:=$(LINUX_DIR)/drivers/net/mhi_net.ko
  AUTOLOAD:=$(call AutoProbe,mhi_net)
endef

define KernelPackage/mhi-net/description
 Driver for MHI network interface
endef

$(eval $(call KernelPackage,mhi-net))
```

Run `make menuconfig`, select the `kmod-mhi-net` package (bus is a dependency and is selected automatically) and compile
your firmware. The drivers are loaded automatically at boot.
