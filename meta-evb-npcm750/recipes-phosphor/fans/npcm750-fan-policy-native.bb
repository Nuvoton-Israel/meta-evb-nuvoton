SUMMARY = "Fan policy for npcm750"
PR = "r1"

inherit native
inherit obmc-phosphor-license
inherit phosphor-dbus-monitor

SRC_URI += "file://air-cooled.yaml"

do_install() {
        install -D ${WORKDIR}/air-cooled.yaml ${D}${config_dir}/air-cooled.yaml
}
