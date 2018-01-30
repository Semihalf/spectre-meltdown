#!/bin/sh

TEST_RUNS="10"
OPTIONS="-Os -O0 -O1 -O2 -O3"
LOG="test.log"
EXPECTED_LOG_SIZE="2622"
EXPECTED_SPECTRE_LOG_SIZE="263"
POWER_MODES="powersave performance"
CFLAGS="-g -Wall -Werror"

SRC="$(ls *.c)"
SRC="${SRC%*.c}"


for POWER_MODE in ${POWER_MODES}; do
	echo "===> Setting CPUs in ${POWER_MODE} mode..."
	find '/sys/devices/system/cpu/' -name 'scaling_governor' \
		| while read F; do
			echo ${POWER_MODE} | sudo tee "${F}" > /dev/null
		done

for SPECTRE in "" "0"; do

for OPT in ${OPTIONS}; do
	if ! gcc ${OPT} -o ${SRC}${OPT} ${SRC}.c; then
		exit 1
	fi

	count="0"
	errors="0"
	while [ "${count}" != "${TEST_RUNS}" ] ; do 
		count=$((${count} + 1))
		./${SRC}${OPT} ${SPECTRE} > ${LOG}
		fsize=$(stat -c "%s" ${LOG} )
		if [ "x${fsize}" != "x${EXPECTED_LOG_SIZE}" -a \
			"x${fsize}" != "x${EXPECTED_SPECTRE_LOG_SIZE}" ]; then
			errors=$(($errors + 1))
		fi
	done
	rm -f ${SRC}${OPT}
	rm -f ${LOG}

	if [ -n "${SPECTRE}" ]; then
		echo "SPECTRE${OPT}: ${errors}/${count} = $((${errors}*1000/${count}))‰ errors"
	else
		echo "MELTDOWN${OPT}: ${errors}/${count} = $((${errors}*1000/${count}))‰ errors"
	fi
done


done # SPECTRE

done # POWER_MODE
