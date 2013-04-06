include $(TOPDIR)/rules.mk

PKG_NAME:=shadowsocks-libev
PKG_VERSION:=1.0
PKG_RELEASE=$(PKG_SOURCE_VERSION)

PKG_SOURCE_PROTO:=git
PKG_SOURCE_URL:=https://github.com/madeye/shadowsocks-libev.git
PKG_SOURCE_SUBDIR:=$(PKG_NAME)-$(PKG_VERSION)
PKG_SOURCE_VERSION:=2c732efaac102fc196ce28893c9a9efa2bff0392
PKG_SOURCE:=$(PKG_NAME)-$(PKG_VERSION)-$(PKG_SOURCE_VERSION).tar.gz
PKG_MAINTAINER:=haohaolee <hayatelee@gmail.com>
# PKG_MIRROR_MD5SUM:=

#PKG_BUILD_DEPENDS:=libpthread
PKG_INSTALL:=1 
PKG_FIXUP:=autoreconf 

PKG_BUILD_PARALLEL:=1

include $(INCLUDE_DIR)/package.mk

define Package/shadowsocks-libev
  SECTION:=net
  CATEGORY:=Network
  DEPENDS:=
  TITLE:=shadowsocks-libev
endef

define Package/shadowsocks-libev/description
Shadowsocks-libev is a lightweight secured scoks5 proxy for embedded devices and low end boxes..
endef

define Package/shadowsocks-libev/conffiles
/etc/config/shadowsocks.json
endef

TARGET_CFLAGS += -I$(STAGING_DIR)/usr/include -I$(STAGING_DIR)/usr/include/libev
TARGET_LDFLAGS += -L$(STAGING_DIR)/usr/lib/libev -L$(STAGING_DIR)/usr/lib -lm

define Package/shadowsocks-libev/install
	$(INSTALL_DIR) $(1)/usr/bin $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/ss-local $(1)/usr/bin/ss-local
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/src/ss-redir $(1)/usr/bin/ss-redir
	$(INSTALL_BIN) ./files/shadowsocks.init $(1)/etc/init.d/shadowsocks
	$(INSTALL_CONF) ./files/shadowsocks.json $(1)/etc/config/shadowsocks.json
endef

$(eval $(call BuildPackage,shadowsocks-libev))

