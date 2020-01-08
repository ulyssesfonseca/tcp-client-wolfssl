MAIN_FILE = teste-wolfssl
DIR_BUILD = build

all: projeto

projeto: ${MAIN_FILE}.c
	$(shell mkdir -p ${DIR_BUILD})
	gcc ${MAIN_FILE}.c -o ./${DIR_BUILD}/${MAIN_FILE} -lwolfssl

clean:
	rm  -rf ./${DIR_BUILD}/ *.o

run: projeto ./${DIR_BUILD}/${MAIN_FILE}
	./${DIR_BUILD}/${MAIN_FILE}
