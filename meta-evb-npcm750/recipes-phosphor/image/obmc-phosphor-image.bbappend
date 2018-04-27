OBMC_IMAGE_EXTRA_INSTALL_append = " phosphor-ipmi-host"
OBMC_IMAGE_EXTRA_INSTALL_append = " phosphor-ipmi-kcs"
OBMC_IMAGE_EXTRA_INSTALL_append = " phosphor-cooling-type"

IMAGE_INSTALL_append = " obmc-mgr-sensor \
                         lmsensors-fancontrol \
                         lmsensors-pwmconfig \
                         lmsensors-sensord \
                         lmsensors-sensors \
                         iperf \
                       "
