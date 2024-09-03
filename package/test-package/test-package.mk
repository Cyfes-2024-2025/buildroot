################################################################################
#
# test-package package
#
################################################################################

TEST_PACKAGE_VERSION = 1.0
TEST_PACKAGE_SITE = package/test-package/src
TEST_PACKAGE_SITE_METHOD = local

define TEST_PACKAGE_BUILD_CMDS
	$(MAKE) CC="$(TARGET_CC)" LD="$(TARGET_LD)" -C $(@D)
endef

define TEST_PACKAGE_INSTALL_TARGET_CMDS
	$(INSTALL) -D -m 0755 $(@D)/testpackage $(TARGET_DIR)/usr/bin
endef

$(eval $(generic-package))
