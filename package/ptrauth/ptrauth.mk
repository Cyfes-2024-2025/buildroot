################################################################################
#
# ptrauth package
#
################################################################################

PTRAUTH_VERSION = 1.0.0
PTRAUTH_SITE = package/ptrauth/src
PTRAUTH_SITE_METHOD = local
PTRAUTH_LICENSE = GPL-2.0

$(eval $(kernel-module))
$(eval $(generic-package))
