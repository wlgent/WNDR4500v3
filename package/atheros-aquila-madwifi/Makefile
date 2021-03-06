# 
# Copyright (C) 2006 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#
# $Id: Makefile 5196 2006-10-17 20:52:40Z nbd $
include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
PKG_NAME:=atheros-aquila-madwifi
PKG_VERSION:=
PKG_RELEASE:=1

PKG_SOURCE:=
PKG_SOURCE_URL:=
PKG_MD5SUM:=
PKG_CAT:=zcat

PKG_CO_TAG=atheros-br
PKG_GIT_TREEISH=$(CONFIG_ATHEROS_MADWIFI_GIT_TREEISH)
PKG_BUILD_DIR:=$(KERNEL_BUILD_DIR)/$(PKG_NAME)

AR531X_KERNEL_CROSS:=mips-linux-

include $(INCLUDE_DIR)/package.mk

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_DFS
  DFS_ENABLE:=1
  DFS_MODULE:=$(PKG_BUILD_DIR)/lmac/dfs/ath_dfs.$(LINUX_KMOD_SUFFIX)
else
  DFS_ENABLE:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_MCAST_ENHANCEMENT
  MCAST_ENHANCEMENT_ENABLE:=1
else
  MCAST_ENHANCEMENT_ENABLE:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_SW_CRYPTO
  NO_SW_CRYPTO:=0
else
  NO_SW_CRYPTO:=1
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_AR9300
  SUPPORT_AR9300:=1
else
  SUPPORT_AR9300:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_HORNET
  SUPPORT_HORNET:=1
else
  SUPPORT_HORNET:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_IQUE
  SUPPORT_IQUE:=1
else
  SUPPORT_IQUE:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_IQUE_EXT
  SUPPORT_IQUE_EXT:=1
else
  SUPPORT_IQUE_EXT:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_PAPRD
  SUPPORT_PAPRD:=1
else
  SUPPORT_PAPRD:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_NO_5G_SUPPORT
  NO_5G_SUPPORT:=1
else
  NO_5G_SUPPORT:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_RPTPLACEMENT
  SUPPORT_RPTPLACEMENT:=1
else
  SUPPORT_RPTPLACEMENT:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_VOWEXT
  SUPPORT_VOWEXT:=1
else
  SUPPORT_VOWEXT:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_VOW_EXT_STATS
  SUPPORT_VOW_EXT_STATS:=1
else
  SUPPORT_VOW_EXT_STATS:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_VOW_TIDSCHED
  SUPPORT_VOW_TIDSCHED:=1
else
  SUPPORT_VOW_TIDSCHED:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_VOW_LOGLATENCY
  SUPPORT_VOW_LOGLATENCY:=1
else
  SUPPORT_VOW_LOGLATENCY:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_CFEND
  SUPPORT_CFEND:=1
else
  SUPPORT_CFEND:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_DESCFAST
  SUPPORT_DESCFAST:=1
else
  SUPPORT_DESCFAST:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_TDLS
  BOARD_OPTIONS+= ATH_SUPPORT_TDLS=1
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_GREEN_AP
  SUPPORT_GREEN_AP:=1
else
  SUPPORT_GREEN_AP:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_AR5416_INT_MITIGATION
  SUPPORT_AR5416_INT_MITIGATION:=1
else
  SUPPORT_AR5416_INT_MITIGATION:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_CAP_AMSDU
  SUPPORT_CAP_AMSDU:=1
else
  SUPPORT_CAP_AMSDU:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_BUILD_OPTIMIZED
  BUILD_OPTIMIZED:=1
else
  BUILD_OPTIMIZED:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_HOWL
  HOWL_SUPPORT:=1
else
  HOWL_SUPPORT:=0
endif

ifdef CONFIG_ATHEROS_MADWIFI_PLATFORM_PATCH
  PLATFORM_PATCH_DIR:=./patches-$(BOARD)
endif

RATE_CONTROL:=atheros

ifeq ($(ARCH),mips)
  HAL_TARGET:=mipsisa32-be-elf
  KERNEL_ARCH=mips
endif
ifeq ($(ARCH),mipsel)
  HAL_TARGET:=mips-le-elf
  KERNEL_ARCH=mips
endif
ifeq ($(ARCH),i386)
  HAL_TARGET:=i386-elf
  KERNEL_ARCH=i386
endif

BUS:=PCI
ifneq ($(CONFIG_LINUX_2_6_AR71XX),)
  BUS:=PCI
endif
ifneq ($(CONFIG_LINUX_2_6_ARUBA),)
  BUS:=PCI AHB	# no suitable HAL for AHB yet.
endif


ATH_TOOLS:= athstats apstats athstatsclr wlanconfig cgiMain radartool

MADWIFI_AUTOLOAD:= \
	adf \
	asf \
	ath_hal \
	ath_rate_atheros \
	ath_dev \
	umac

ifdef CONFIG_ATHEROS_MADWIFI_SUPPORT_PKTLOG
  PKTLOG_MODULE:=$(PKG_BUILD_DIR)/lmac/ath_pktlog/ath_pktlog.$(LINUX_KMOD_SUFFIX)
  ATH_TOOLS+=pktlogconf pktlogdump
  MADWIFI_AUTOLOAD+=ath_pktlog
  REMOVE_PKTLOG=0
else
  REMOVE_PKTLOG=1
endif

define KernelPackage/atheros-aquila-madwifi
  SUBMENU:=Wireless Drivers
  TITLE:=Driver for Atheros wireless chipsets
  URL:=http://madwifi.org/
  VERSION:=$(LINUX_VERSION)+$(PKG_VERSION)-$(BOARD)-$(PKG_RELEASE)
  FILES:= \
		$(PKG_BUILD_DIR)/adf/adf.$(LINUX_KMOD_SUFFIX) \
		$(PKG_BUILD_DIR)/asf/asf.$(LINUX_KMOD_SUFFIX) \
		$(PKG_BUILD_DIR)/lmac/ath_dev/ath_dev.$(LINUX_KMOD_SUFFIX) \
		$(PKG_BUILD_DIR)/lmac/ext/wlan_ext.$(LINUX_KMOD_SUFFIX) \
		$(PKG_BUILD_DIR)/os/linux/ath_hal/ath_hal.$(LINUX_KMOD_SUFFIX) \
		$(PKTLOG_MODULE) \
		$(PKG_BUILD_DIR)/lmac/ratectrl/ath_rate_atheros.$(LINUX_KMOD_SUFFIX) \
		$(PKG_BUILD_DIR)/lmac/tx99/hst_tx99.$(LINUX_KMOD_SUFFIX) \
		$(DFS_MODULE) \
		$(PKG_BUILD_DIR)/umac/umac.$(LINUX_KMOD_SUFFIX)
  # AUTOLOAD:=$(call AutoLoad,50,$(MADWIFI_AUTOLOAD))
endef

ifneq ($(CONFIG_TARGET_dniwndr3700u2631),)
  MADWIFI_DRIVER_SPEC_OPTS+= \
	DNI_EXTRA_HAL_INCS="-I$(LINUX_DIR)/arch/mips/include/asm/mach-ar71xx" \
	USEMARCH="mips32"
  BOARD_FLAGS+=-DWORKAROUND_FOR_OPENWRT_WNDR3700
endif

ifdef CONFIG_ATHEROS_MADWIFI_2G_MAC_ADDR_LOC
  BOARD_FLAGS+=-DWLAN_2G_MAC_ADDR=$(CONFIG_ATHEROS_MADWIFI_2G_MAC_ADDR_LOC)
endif

ifdef CONFIG_ATHEROS_MADWIFI_5G_MAC_ADDR_LOC
  BOARD_FLAGS+=-DWLAN_5G_MAC_ADDR=$(CONFIG_ATHEROS_MADWIFI_5G_MAC_ADDR_LOC)
endif

ifdef CONFIG_ATHEROS_MADWIFI_USE_CLIENT_BRIDGE
  BOARD_FLAGS+=-DENABLE_CLIENT_BRIDGE
  BOARD_FLAGS+=-DDNI_EXTEND_FUNCS
endif

ifdef CONFIG_ATHEROS_MADWIFI_DISPLAY_SCAN_IN_PROC
  BOARD_FLAGS+=-DDISPLAY_SCAN_RESULT_IN_PROC
  BOARD_FLAGS+=-DENABLE_DNI_SYSCTL
endif

ifneq ($(CONFIG_TARGET_wndr4500v3),)
  export CFG_BOARD_TYPE=ap152
  include qca-configs/config.board956x
  BOARD_FLAGS+=-DNETGEAR_ACL
  BUS=dual
  BOARD_OPTIONS+= AH_CAL_IN_FLASH_AHB=1 \
		AH_CAL_IN_FLASH_PCI=1 \
		AH_CAL_RADIOS_PCI=1 \
		AH_CAL_LOCATIONS_PCI=$(CONFIG_ATHEROS_MADWIFI_CAL_LOCATIONS_PCI) \
		AH_CAL_RADIOS_AHB=1 \
		AH_CAL_LOCATIONS_AHB=$(CONFIG_ATHEROS_MADWIFI_CAL_LOCATIONS_AHB) \
		ATH_SUPPORT_LED=0 \
		ATH_DEBUG=1 \
		ATH_LED_CUSTOMER=CUSTOMER_NETGEAR \
		GPIO_PIN_FUNC_0=0 \
		GPIO_PIN_FUNC_1=0 \
		GPIO_PIN_FUNC_2=0 
else
  BOARD_OPTIONS+= AH_CAL_IN_FLASH=1 \
		AH_CAL_RADIOS=$(CONFIG_ATHEROS_MADWIFI_RADIOS) \
		AH_CAL_LOCATIONS=$(CONFIG_ATHEROS_MADWIFI_CAL_LOCATIONS) \
		AH_SUPPORT_OWL=0
  ifneq ($(CONFIG_TARGET_wnr1000v4),)
    BUS=AHB
    BOARD_OPTIONS+=AH_SUPPORT_SOWL=0 \
	AH_SUPPORT_EEPROM_AR9330=1 \
	ATH_TRAFFIC_FAST_RECOVER=1 \
	ATH_WDS_INTEROP=1
  endif
endif


MADWIFI_DRIVER_SPEC_OPTS+= \
		KERNELPATH="$(LINUX_DIR)" \
		KERNELARCH=$(KERNEL_ARCH) \
		KERNELVER=$(LINUX_VERSION) \
		TARGET="$(HAL_TARGET)"

MADWIFI_ENVOPTS:= \
		PATH="$(KERNEL_STAGING_DIR)/bin:$(TARGET_PATH)" \
		ARCH="$(LINUX_KARCH)" \
		CROSS_COMPILE="$(TARGET_KERNEL_CROSS)" \
		TOOLPREFIX="$(TARGET_KERNEL_CROSS)" \
		TOOLPATH="$(TARGET_KERNEL_CROSS)" \
		ATHEROSPATH="$(PKG_BUILD_DIR)" \
		ATH_RATE="$(PKG_BUILD_DIR)/lmac/ratectrl" \
		HAL="$(PKG_BUILD_DIR)/hal" \
		COMMON_CFLAGS="-DCONFIG_NO_SAVE_CALDATA -DNETGEAR_CUSTOMISED_LED -DNETGEAR_WLAN_LOG -DENABLE_DNI_SYSCTL -DWPS_NOTIFICATION -DDNI_HOSTAP_JUDGE_PIN_LENGTH -DNETGEAR_CUSTOMISED_WEP_KEY -DNETGEAR_CUSTOM_MIC -DNETGEAR_RTS_DEF -DNETGEAR_DISABLE_WPS_IE -DMORE_TPSCALE -DNETGEAR_CUSTOMISED_DFS -DUSE_DNI_DMAPOOL -DDNI_SHOW_VAP_STATUS $(BOARD_FLAGS)"

MADWIFI_ATHOPTS:= \
		BUILD_UMAC=1 \
		BUS=$(BUS) \
		AH_SUPPORT_AR9300=$(SUPPORT_AR9300) \
		AH_SUPPORT_HORNET=$(SUPPORT_HORNET) \
		ATH_RXBUF=$(CONFIG_ATHEROS_MADWIFI_RXBUF) \
		ATH_TXBUF=$(CONFIG_ATHEROS_MADWIFI_TXBUF) \
		ATH_CAP_AMSDU=$(SUPPORT_CAP_AMSDU) \
		REMOVE_PKT_LOG=$(REMOVE_PKTLOG) \
		AH_SUPPORT_HOWL=$(HOWL_SUPPORT) \
		AR5416_INT_MITIGATION=$(SUPPORT_AR5416_INT_MITIGATION) \
		ATH_SUPPORT_DFS=$(DFS_ENABLE) \
		AH_WAR_52640=1 \
		ATH_WDS_INTEROP=1 \
		WPS_LED_GPIO_PIN=0 \
		ATH_CONFIG_NVRAM=0 \
		ATH_SUPPORT_IQUE=$(SUPPORT_IQUE) \
		ATH_SUPPORT_IQUE_EXT=$(SUPPORT_IQUE_EXT) \
		ATH_SUPPORT_PAPRD=$(SUPPORT_PAPRD) \
		ATH_NO_5G_SUPPORT=$(NO_5G_SUPPORT) \
		IEEE80211_MCAST_ENHANCEMENT=$(MCAST_ENHANCEMENT_ENABLE) \
		ATH_EXT_AP=1 \
		ATH_SUPPORT_VOWEXT=$(SUPPORT_VOWEXT) \
		ATH_VOW_EXT_STATS=$(SUPPORT_VOW_EXT_STATS) \
		VOW_TIDSCHED=$(SUPPORT_VOW_TIDSCHED) \
		VOW_LOGLATENCY=$(SUPPORT_VOW_LOGLATENCY) \
		ATH_SUPPORT_CFEND=$(SUPPORT_CFEND) \
		ATH_SUPPORT_DESCFAST=$(SUPPORT_DESCFAST) \
		ATH_SUPPORT_GREEN_AP=$(SUPPORT_GREEN_AP) \
		ATH_NO_SW_CRYPTO=$(NO_SW_CRYPTO) \
		BUILD_OPTIMIZED=$(BUILD_OPTIMIZED) \
		$(BOARD_OPTIONS) \
		UMAC_SUPPORT_NAWDS=1

MADWIFI_DRIVEROPTS:= $(MADWIFI_DRIVER_SPEC_OPTS) $(MADWIFI_ENVOPTS) $(MADWIFI_ATHOPTS)
MADWIFI_TOOLOPTS:= $(MADWIFI_ENVOPTS) $(MADWIFI_ATHOPTS) $(MADWIFI_DRIVER_SPEC_OPTS)

ifeq ($(BUS),AHB)
  MADWIFI_TOOLOPTS+=KERNELPATH="$(LINUX_DIR)"
endif

define KernelPackage/atheros-aquila-madwifi/config
	source "$(SOURCE)/Config.in"
endef

define Build/Prepare
	$(CP) $(GIT_HOME)/madwifi-11n.git/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
endef

define Build/InstallDev
endef

define Build/UninstallDev
	rm -rf	$(STAGING_DIR)/usr/include/madwifi
endef

define KernelPackage/atheros-aquila-madwifi/install
	mkdir -p $(1)/etc/init.d
	mkdir -p $(1)/lib/modules/$(LINUX_VERSION)
	mkdir -p $(1)/sbin
	$(CP) $(foreach file,$(ATH_TOOLS),$(PKG_BUILD_DIR)/os/linux/tools/$(file)) $(1)/sbin
	ln -sf /sbin/cgiMain $(1)/sbin/cfg
endef

$(eval $(call KernelPackage,atheros-aquila-madwifi))
