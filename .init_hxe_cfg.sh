#!/bin/bash


#
# Prompt local host name
#
promptHostName() {
	local host=""
	while [ 1 ]; do
		read -p "Enter host name [${HOST_NAME}]: " host
		if [ -z "${host}" -a -n "${HOST_NAME}" ]; then
			break
		elif [ -z "${host}" -a -z "${HOST_NAME}" ]; then
			echo
			echo "Please enter local host name."
			echo
		elif [[ ${host} =~ ^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$ ]]; then
			HOST_NAME="${host}"
			break
		else
			echo
			echo "\"$host\" is not a valid host name."
			echo
		fi
	done

	echo
}

#
# Prompt domain name
#
promptDomainName() {
	local domain=""
	while [ 1 ]; do
		read -p "Enter domain name [${DOMAIN_NAME}]: " domain
		if [ -z "${domain}" -a -n "${DOMAIN_NAME}" ]; then
			break
		elif [ -z "${domain}" -a -z "${DOMAIN_NAME}" ]; then
			echo
			echo "Please enter domain name (example: mycompany.com)."
			echo
		elif ! $(isValidHostName "$domain"); then
			echo
			echo "\"$domain\" is not a valid domain name."
			echo
		else
			DOMAIN_NAME="${domain}"
			break
		fi
	done

	echo
}

# Prompt user password
# arg 1: user name
# arg 2: variable name to store password value
#
promptPwd() {
	local pwd=""
	while [ 1 ]; do
		read -r -s -p "Enter ${1} password : " pwd
		if [ -z "$pwd" ]; then
			echo
			echo "Invalid empty password. Please re-enter."
			echo
		else
			break
		fi
	done

	echo
	eval $2=\$pwd

	echo
}

#
# Prompt new user password
# arg 1: user name
# arg 2: variable name to store password value
#
promptNewPwd() {
	local msg=""
	local showPolicy=0
	local pwd=""
	local confirm_pwd=""
	echo
	echo "Password must be at least 8 characters in length.  It must contain at least"
	echo "1 uppercase letter, 1 lowercase letter, and 1 number.  Special characters"
	echo "are allowed, except \\ (backslash), ' (single quote), \" (double quotes),"
	echo "\` (backtick), and \$ (dollar sign)."
	echo
	while [ 1 ] ; do
		read -r -s -p "New ${1} password: " pwd
		echo

		if [ "$pwd" == "${OLD_MASTER_PWD}" ]; then
			echo
			echo "Invalid password: password already been used."
			echo
			continue
		fi

		if [ `echo "$pwd" | wc -c` -le 8 ]; then
			msg="too short"
			showPolicy=1
		fi
		if ! echo "$pwd" | grep "[A-Z]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing uppercase letter"
			else
				msg="$msg, missing uppercase letter"
			fi
			showPolicy=1
		fi
		if ! echo "$pwd" | grep "[a-z]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing lowercase letter"
			else
				msg="$msg, missing lowercase letter"
			fi
			showPolicy=1
		fi
		if ! echo "$pwd" | grep "[0-9]" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="missing a number"
			else
				msg="$msg, missing a number"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '\' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\\ (backslash) not allowed"
			else
				msg="$msg, \\ (backslash) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F "'" >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="' (single quote) not allowed"
			else
				msg="$msg, ' (single quote) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '"' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\" (double quotes) not allowed"
			else
				msg="$msg, \" (double quotes) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '`' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\` (backtick) not allowed"
			else
				msg="$msg, \` (backtick) not allowed"
			fi
			showPolicy=1
		fi
		if echo "$pwd" | grep -F '$' >& /dev/null; then
			if [ -z "$msg" ]; then
				msg="\$ (dollar sign) not allowed"
			else
				msg="$msg, \$ (dollar sign) not allowed"
			fi
			showPolicy=1
		fi
		if [ $showPolicy -eq 1 ]; then
			echo
			echo "Invalid password: ${msg}." | fold -w 80 -s
			echo
			echo "Password must meet all of the following criteria:"
			echo "- 8 or more letters"
			echo "- At least 1 uppercase letter"
			echo "- At least 1 lowercase letter"
			echo "- At least 1 number"
			echo
			echo "Special characters are optional; except \\ (backslash), ' (single quote),"
			echo "\" (double quotes), \` (backtick), and \$ (dollar sign)."
			echo
			msg=""
			showPolicy=0
			continue
		fi

		crack_msg=`/usr/sbin/cracklib-check <<EOF
${pwd}
EOF`
		crack_msg=`awk 'BEGIN { FS = ": " } ; {print $2}' <<EOF
${crack_msg}
EOF`

		if [ "${crack_msg}" != "OK" ] ; then
			echo ""
			echo "Invalid password: ${crack_msg}"
			echo ""
			continue
		fi

		read -r -s -p "Confirm \"${1}\" password: " confirm_pwd
		echo
		if [ "${pwd}" != "${confirm_pwd}" ]; then
			echo ""
			echo "Passwords do not match."
			echo ""
			continue
		fi

		eval $2=\$pwd

		break;
	done

	echo
}

#
# Prompt proxy host and port
#
promptProxyInfo() {
	getSystemHTTPProxy

	if [ -d "/hana/shared/${SID}/xs/router" ]; then
		while [ 1 ] ; do
			read -p "Do you need to use proxy server to access the internet? (Y/N): " tmp
			if [ "$tmp" == "Y" -o "$tmp" == "y" ]; then
				SETUP_PROXY=1
				break
			elif [ "$tmp" == "N" -o "$tmp" == "n" ]; then
				SETUP_PROXY=0
				echo
				return
			else
				echo "Invalid input.  Enter \"Y\" or \"N\"."
			fi
		done

		# Proxy host
		while [ 1 ]; do
			read -p "Enter proxy host name [$SYSTEM_PROXY_HOST]: " tmp
			if [ -z "$tmp" ]; then
				if [ -n "$SYSTEM_PROXY_HOST" ]; then
					tmp="$SYSTEM_PROXY_HOST"
				else
					continue
				fi
			fi
			if ! $(isValidHostName "$tmp"); then
				echo
				echo "\"$tmp\" is not a valid host name or IP address."
				echo
			else
				PROXY_HOST="$tmp"
				break
			fi
		done

		# Proxy port
		while [ 1 ]; do
			read -p "Enter proxy port number [$SYSTEM_PROXY_PORT]: " tmp
			if [ -z "$tmp" ]; then
				if [ -n "$SYSTEM_PROXY_PORT" ]; then
					tmp="$SYSTEM_PROXY_PORT"
				else
					continue
				fi
			fi
			if ! $(isValidPort "$tmp"); then
				echo
				echo "\"$tmp\" is not a valid port number."
				echo "Enter number between 1 and 65535."
				echo
			else
				PROXY_PORT="$tmp"
				break
			fi
		done

		# No proxy hosts
		read -p "Enter comma separated domains that do not need proxy [$SYSTEM_NO_PROXY_HOST]: " tmp
		if [ -z "$tmp" ]; then
			NO_PROXY_HOST="$SYSTEM_NO_PROXY_HOST"
		else
			NO_PROXY_HOST="$tmp"
			NO_PROXY_HOST="$(addLocalHostToNoProxy "$NO_PROXY_HOST")"
		fi

		echo
	fi
}

promptWaitXSAConfig() {
	local tmp=""
	if [ $HAS_XSA -eq 1 ]; then
		echo "XSA configuration may take a while.  Do you wish to wait for XSA configuration to finish?"
		echo "If you enter no, XSA will be configured in background after server completes."
		echo
		while [ 1 ]; do
			read -p "Wait for XSA configuration to finish (Y/N) [Y] : " tmp
			if [ -z "${tmp}" ] || [[ "${tmp}" =~ [Y,y] ]]; then
				echo
				WAIT_XSA_CONFIG=1
				return
			elif [[ "${tmp}" =~ [N,n] ]]; then
				echo
				WAIT_XSA_CONFIG=0
				return
			fi
		done
	fi
}

#
# Trim leading and trailing spaces
#
trim()
{
        trimmed="$1"
        trimmed=${trimmed%% }
        trimmed=${trimmed## }
        echo "$trimmed"
}

formatNoProxyHost() {
	if [ -z "$1" ]; then
		return
	fi

	local no_ph=""
	IFS=',' read -ra hlist <<< "$1"
	for i in "${hlist[@]}"; do
		tmp=$(trim "$i")
		if [ -n "${tmp}" ]; then
			if [[ "${tmp}" =~ ^[0-9]+\. ]] || [[ "${tmp}" =~ [Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt] ]]; then
				no_ph="${no_ph}|${tmp}"
			elif echo ${tmp} | grep -i "^${HOST_NAME}$" >& /dev/null; then
				no_ph="${no_ph}|${tmp}"
			elif echo ${tmp} | grep -i "^${HOST_NAME}\.?*" >& /dev/null; then
				no_ph="${no_ph}|${tmp}"
			elif [[ "${tmp}" =~ ^\. ]]; then
				no_ph="${no_ph}|*${tmp}"
			else
				no_ph="${no_ph}|*.${tmp}"
			fi
		fi
	done
	echo ${no_ph} | sed 's/^|//'
}

#
# Get the system proxy host and port
#
getSystemHTTPProxy() {
	local url="$https_proxy"
	local is_https_port=1

	if [ -z "$url" ]; then
		url="$http_proxy"
		is_https_port=0
	fi
	if [ -z "$url" ] && [ -f /etc/sysconfig/proxy ]; then
		url=`grep ^HTTPS_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		is_https_port=1
	fi
	if [ -z "$url" ] && [ -f /etc/sysconfig/proxy ]; then
		url=`grep ^HTTP_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		is_https_port=0
	fi

	url="${url%\"}"
	url="${url#\"}"
	url="${url%\'}"
        url="${url#\'}"

	if [ -z "$url" ]; then
		SETUP_PROXY=0
		return
	fi

	# Get proxy host
	SYSTEM_PROXY_HOST=$url
	if echo $url | grep -i '^http' >& /dev/null; then
		SYSTEM_PROXY_HOST=`echo $url | cut -d '/' -f3 | cut -d':' -f1`
	else
		SYSTEM_PROXY_HOST=`echo $url | cut -d '/' -f1 | cut -d':' -f1`
	fi

	if [ -n "${SYSTEM_PROXY_HOST}" ]; then
		SETUP_PROXY=1
	fi

	# Get proxy port
	if echo $url | grep -i '^http' >& /dev/null; then
		if echo $url | cut -d '/' -f3 | grep ':' >& /dev/null; then
			SYSTEM_PROXY_PORT=`echo $url | cut -d '/' -f3 | cut -d':' -f2`
		elif [ $is_https_port -eq 1 ]; then
			SYSTEM_PROXY_PORT="443"
		else
			SYSTEM_PROXY_PORT="80"
		fi
	else
		if echo $url | cut -d '/' -f1 | grep ':' >& /dev/null; then
			SYSTEM_PROXY_PORT=`echo $url | cut -d '/' -f1 | cut -d':' -f2`
		elif [ $is_https_port -eq 1 ]; then
			SYSTEM_PROXY_PORT="443"
		else
			SYSTEM_PROXY_PORT="80"
		fi
        fi

	# Get no proxy hosts
	SYSTEM_NO_PROXY_HOST="$no_proxy"
	if [ -z "$SYSTEM_NO_PROXY_HOST" ] && [ -f /etc/sysconfig/proxy ]; then
		SYSTEM_NO_PROXY_HOST=`grep ^NO_PROXY /etc/sysconfig/proxy | cut -d'=' -f2`
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST%\"}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST#\"}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST%\'}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST#\'}"
	fi
	if [ -z "$SYSTEM_NO_PROXY_HOST" ] && [ -f /etc/sysconfig/proxy ]; then
		SYSTEM_NO_PROXY_HOST=`grep ^no_proxy /etc/sysconfig/proxy | cut -d'=' -f2`
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST%\"}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST#\"}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST%\'}"
		SYSTEM_NO_PROXY_HOST="${SYSTEM_NO_PROXY_HOST#\'}"
	fi
	if [[ -n "$SYSTEM_NO_PROXY_HOST" ]]; then
		SYSTEM_NO_PROXY_HOST="$(addLocalHostToNoProxy "$SYSTEM_NO_PROXY_HOST")"
	fi
}

addLocalHostToNoProxy() {
	if [ -z "$1" ]; then
		return
	fi

	local no_ph=$1
	local has_localhost=0
	local has_localhost_name=0
	local has_localhost_domain=0
	local has_localhost_ip=0

	IFS=',' read -ra hlist <<< "$no_ph"
	for i in "${hlist[@]}"; do
		tmp=$(trim "$i")
		if [ -n "${tmp}" ]; then
			if [[ "${tmp}" =~ [Ll][Oo][Cc][Aa][Ll][Hh][Oo][Ss][Tt] ]]; then
				has_localhost=1
			elif echo ${tmp} | grep -i "^${HOST_NAME}\.${DOMAIN_NAME}$" >& /dev/null; then
				has_localhost_domain=1
			elif echo ${tmp} | grep -i "^${HOST_NAME}$" >& /dev/null; then
				has_localhost_name=1
			elif [[ "$tmp" == "127.0.0.1" ]]; then
				has_localhost_ip=1
			fi
		fi
	done

	if [ $has_localhost_ip -eq 0 ]; then
		no_ph="127.0.0.1, ${no_ph}"
	fi
	if [ $has_localhost_domain -eq 0 ]; then
		no_ph="${HOST_NAME}.${DOMAIN_NAME}, ${no_ph}"
	fi
	if [ $has_localhost_name -eq 0 ]; then
		no_ph="${HOST_NAME}, ${no_ph}"
	fi
	if [ $has_localhost -eq 0 ]; then
		no_ph="localhost, ${no_ph}"
	fi

	echo ${no_ph}
}

isValidHostName() {
	local hostname_regex='^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
	echo "$1" | egrep $hostname_regex >& /dev/null
}

isValidPort() {
	if [[ $1 =~ ^[0-9]?+$ ]]; then
		if [ $1 -ge 1 ] && [ $1 -le 65535 ]; then
			return 0
		else
			return 1
		fi
	else
		return 1
	fi
}

setWebIDEProxy() {
	if [ $SETUP_PROXY -eq 1 ] && [ $HAS_XSA -eq 1 ]; then
		echo "Set proxy for WEB_IDE..."

		echo "Login to XSA services..."
		xs login -u xsa_admin -p ${MASTER_PWD} -s SAP
		if [ $? -ne 0 ]; then
			echo
			echo "Cannot login to XSA services.  Please check HANA has started and login/password are correct."
			exit 1
		fi

		echo "Check/Wait for di-local-npm-registry and di-core apps to start.  This may take a while..."
		xs wait-for-apps --timeout 3600 --apps "di-local-npm-registry,di-core"
		if [ $? -ne 0 ]; then
			echo
			echo "Waiting for apps to start has timeout."
			exit 1
		fi

		if [ -n "${PROXY_PORT}" ]; then
			xs set-env di-local-npm-registry HTTP_PROXY "http://${PROXY_HOST}:${PROXY_PORT}"
		else
			xs set-env di-local-npm-registry HTTP_PROXY "http://${PROXY_HOST}"
		fi
		if [ $? -ne 0 ]; then
			exit 1
		fi
		xs set-env di-local-npm-registry NO_PROXY "${NO_PROXY_HOST}"
		if [ $? -ne 0 ]; then
			exit 1
		fi

		xs restage di-local-npm-registry
		if [ $? -ne 0 ]; then
			exit 1
		fi
		xs restart di-local-npm-registry
		if [ $? -ne 0 ]; then
			exit 1
		fi

		xs set-env di-core JBP_CONFIG_JAVA_OPTS "[java_opts: \"-Dhttp.proxyHost=${PROXY_HOST} -Dhttp.proxyPort=${PROXY_PORT} -Dhttp.nonProxyHosts='$(formatNoProxyHost "$NO_PROXY_HOST")'\"]"
		if [ $? -ne 0 ]; then
			exit 1
		fi

		xs restage di-core
		if [ $? -ne 0 ]; then
			exit 1
		fi
		xs restart di-core
		if [ $? -ne 0 ]; then
			exit 1
		fi
	fi
}

printSummary() {
	echo
	echo "##############################################################################"
	echo "# Summary before execution                                                   #"
	echo "##############################################################################"
	echo "HANA, express edition"
	echo "  Host name                            : ${HOST_NAME}"
	echo "  Domain name                          : ${DOMAIN_NAME}"
	echo "  Master password                      : ********"
	echo "  Log file                             : ${LOG_FILE}"
	if [ -d "/hana/shared/${SID}/xs/router" ]; then
		if [ $WAIT_XSA_CONFIG -eq 1 ]; then
			echo "  Wait for XSA configuration to finish : Yes"
		else
			echo "  Wait for XSA configuration to finish : No"
		fi

		if [ $SETUP_PROXY -eq 1 ]; then
			echo "  Proxy host                           : ${PROXY_HOST}"
			echo "  Proxy port                           : ${PROXY_PORT}"
			echo "  Hosts with no proxy                  : ${NO_PROXY_HOST}"
		else
			echo "  Proxy host                           : N/A"
			echo "  Proxy port                           : N/A"
			echo "  Hosts with no proxy                  : N/A"
		fi
	fi

	echo
	while [ 1 ] ; do
		read -p "Proceed with configuration? (Y/N) : " proceed
		if [ "${proceed}" == "Y" -o "${proceed}" == "y" ]; then
			echo
			return
		elif [ "${proceed}" == "N" -o "${proceed}" == "n" ]; then
			exit 1
		fi
	done
}

#
# Check if server is started
#
checkServer() {
	local hdbinfo_output=""

	echo "Please wait while HANA server starts.  This may take a while..."
	HDB start

	local count=300
	while [ "$count" -gt "0" ]; do
		hdbinfo_output=$(HDB info)
		if echo ${hdbinfo_output} | grep hdbnameserver >& /dev/null; then
			HAS_SERVER=1
			break
		fi
		count=$((count-10))
		sleep 10s
	done
	echo
	if [ $HAS_SERVER -ne 1 ]; then
		echo "Cannot find running HANA server.  Please start HANA with \"HDB start\" command."
		exit 1
	fi

	count=300
	while [ "$count" -gt "0" ]; do
		hdbinfo_output=$(HDB info)
		if echo ${hdbinfo_output} | grep hdbindexserver >& /dev/null; then
			IS_TENANT_STARTED=1
			break
		fi
		count=$((count-10))
		sleep 10s
	done
}

#
# Check if XSA is started
#
checkXSAServer() {
	local hdbinfo_output=""

	if [ -d "/hana/shared/${SID}/xs/router" ]; then
		echo -n "Please wait while XSA starts.  This may take a while..."
		count=900
		HAS_XSA=0
		while [ "$count" -gt "0" ]; do
			hdbinfo_output=$(HDB info)
			if echo ${hdbinfo_output} | grep "/hana/shared/${SID}/xs/router" >& /dev/null; then
				HAS_XSA=1
				echo -n "OK"
				break
			fi
			echo -n "."
			count=$((count-10))
			sleep 10s
		done
		echo
		if [ $HAS_XSA -ne 1 ]; then
			echo "Cannot find running XSA."
			exit 1
		fi
	fi

	hdbinfo_output=$(HDB info)
	if echo ${hdbinfo_output} | grep hdbindexserver >& /dev/null; then
		IS_TENANT_STARTED=1
	fi
}

configXSA() {
	checkXSAServer
	changeXSAPwd
	setWebIDEProxy
	changeProxy
	collectGarbage
}

configXSAInBackground() {
	local status=0
	local status_file="/usr/sap/${SID}/home/xsa_config_status"

	sleep 5s

	rm -f $status_file
	echo "log=$LOG_FILE" > $status_file
	echo "status=in progress" >> $status_file

	exec 0>&-
	exec >& >( awk -v lfile="$LOG_FILE" '{ print strftime("%Y-%m-%d %H:%M:%S :"),$0 >> (lfile); fflush() }' )

	echo
	echo
	echo
	echo
	echo "Start XSA configuration..."
	echo

	checkXSAServer&
	wait $!
	status=$?

	if [ $status -eq 0 ]; then
		changeXSAPwd&
		wait $!
		status=$?
	fi

	if [ $status -eq 0 ]; then
		setWebIDEProxy&
		wait $!
		status=$?
	fi

	if [ $status -eq 0 ]; then
		changeProxy&
		wait $!
		status=$?
	fi

	if [ $status -eq 0 ]; then
		collectGarbage
		install_date=`date --utc`
		sed -i "s/^INSTALL_DATE.*=.*/INSTALL_DATE=$install_date/" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt
		echo
		echo
		echo "*** Congratulations! SAP HANA, express edition 2.0 is configured. ***"
		if [ "$INSTALL_TYPE" == "OVA" -a $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
			echo "*** Please reboot system to take affect. ***"
		fi
		echo

		sed -i 's/^status.*=.*/status=success/g' $status_file

		rm -f "${HOME}/.init_boot"
	else
		echo
		echo
		echo "*** XSA configuration failed.  See log file $LOG_FILE for detail. ***"
		sed -i 's/^status.*=.*/status=fail/g' $status_file
	fi

	exit $status
}

#
# Change user password
# $1 - database
# $2 - user
changeUserPwd() {
	# Check if old password works
	output=$(hdbsql -a -x -quiet 2>&1 <<-EOF
\c -i ${INSTANCE} -d $1 -u $2 -p ${OLD_MASTER_PWD}
EOF
)
	if [ $? -eq 0 ]; then
		# Change password
		output=$(hdbsql -a -x -quiet 2>&1 <<-EOF
\c -i ${INSTANCE} -d $1 -u $2 -p ${OLD_MASTER_PWD}
alter user $2 password "${MASTER_PWD}"
EOF
)
	else
		# Check if new password works
		hdbsql -a -x -quiet <<-EOF
\c -i ${INSTANCE} -d $1 -u $2 -p ${MASTER_PWD}
EOF
		if [ $? -ne 0 ]; then
			echo "Password already changed.  However, the new password you specified is invalid."
			exit 1
		fi
	fi

}

changePwd() {
	echo "Change SYSTEM user password on SystemDB database..."
	changeUserPwd SystemDB SYSTEM

	startTenantDB

	if [ $IS_TENANT_STARTED -eq 1 ]; then
		echo "Change SYSTEM user password on HXE database..."
		changeUserPwd HXE SYSTEM
	fi
}


changeXSAPwd() {
	if [ $HAS_XSA -eq 1 ]; then
		echo "Change XSA_ADMIN user password on SystemDB database..."
		changeUserPwd SystemDB XSA_ADMIN

		echo "Change XSA_DEV user password on SystemDB database..."
		changeUserPwd SystemDB XSA_DEV

		if [ $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
			echo "Change XS API_URL..."
			/hana/shared/${SID}/xs/bin/xs-admin-login --stdin <<-EOF
${MASTER_PWD}
EOF
			if [ $? -ne 0 ]; then
				exit 1
			fi
		fi

		collectGarbage

		echo "Change telemetry technical user (TEL_ADMIN) password on SystemDB database..."
		${HOME}/bin/register_cockpit.sh -action change_pwd -i ${INSTANCE} -d SystemDB <<-EOF
SYSTEM
${MASTER_PWD}
XSA_ADMIN
${MASTER_PWD}
TEL_ADMIN
${OLD_MASTER_PWD}
${MASTER_PWD}
${MASTER_PWD}
${INSTANCE}
EOF
		if [ $? -ne 0 ]; then
			exit 1
		fi

		if [ $IS_TENANT_STARTED -eq 1 ]; then
			collectGarbage

			echo "Change telemetry technical user (TEL_ADMIN) password on HXE database..."
			${HOME}/bin/register_cockpit.sh -action change_pwd -i ${INSTANCE} -d HXE <<-EOF
SYSTEM
${MASTER_PWD}
XSA_ADMIN
${MASTER_PWD}
TEL_ADMIN
${OLD_MASTER_PWD}
${MASTER_PWD}
${MASTER_PWD}
${INSTANCE}
EOF
			if [ $? -ne 0 ]; then
				exit 1
			fi
		fi
	fi
}

changeKey() {
	mkdir -p ${HOME}/root_key.bck
	chmod 700 ${HOME}/root_key.bck

	${HOME}/bin/change_key.sh -d HXE <<-EOF
${INSTANCE}
${MASTER_PWD}
${MASTER_PWD}
${HOME}/root_key.bck
Y
EOF
	if [ $? -ne 0 ]; then
		exit 1
	fi
}

changeProxy() {
	if [ $SETUP_PROXY -eq 1 ] && [ $HAS_XSA -eq 1 ]; then
		collectGarbage

		${HOME}/bin/register_cockpit.sh -action config_proxy -proxy_action enable_http <<-EOF
XSA_ADMIN
${MASTER_PWD}
${INSTANCE}
${PROXY_HOST}
${PROXY_PORT}
${NO_PROXY_HOST}
EOF
		if [ $? -ne 0 ]; then
			exit 1
		fi
	fi
}

changeHostName() {
	if [ $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
		echo "Change host name to ${HOST_NAME}.${DOMAIN_NAME}..."

		sudo truncate -s 0 /etc/hostname
		sudo sh -c "echo \"${HOST_NAME}\" >> /etc/hostname"
		sudo sh -c "sed -i 's/^DHCLIENT_SET_HOSTNAME=.*/DHCLIENT_SET_HOSTNAME=\"no\"/' /etc/sysconfig/network/dhcp"
		sudo sh -c "sed -i 's/^127\\.0\\.0\\.1.\*/127.0.0.1       localhost.${DOMAIN_NAME} localhost/' /etc/hosts"

		if ! grep "^127.0.0.2" /etc/hosts >& /dev/null; then
			sudo sh -c "echo \"127.0.0.2       ${HOST_NAME}.${DOMAIN_NAME} ${HOST_NAME}\" >> /etc/hosts"
		else
			sudo sh -c "sed -i 's/^127\\.0\\.0\\.2.\*/127.0.0.2       ${HOST_NAME}.${DOMAIN_NAME} ${HOST_NAME}/' /etc/hosts"
		fi
		sudo sh -c "sed -i 's/^Host name :.*/Host name : ${HOST_NAME}.${DOMAIN_NAME}/' /etc/issue"
		sudo sh -c "sed -i 's/^myhostname = .*/myhostname = ${HOST_NAME}.${DOMAIN_NAME}/' /etc/postfix/main.cf"

		echo "Restart network service..."
		sudo hostname ${HOST_NAME}
		sudo systemctl restart network
	fi
}

convertTopology() {
	local xsa_args=""
	if [ $HAS_XSA -ne 1 ]; then
		xsa_args="--xs_domain_name=${HOST_NAME}.${DOMAIN_NAME}"
	fi

	if [ $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
		echo "Converting topology to hostname ${HOST_NAME}.${DOMAIN_NAME}..."
		echo "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Passwords>\
	<sapadm_password><![CDATA[HXEHana1]]></sapadm_password>\
	<source_password><![CDATA[$SYSTEM_ADMIN_PWD]]></source_password>\
	<source_system_user_password><![CDATA[HXEHana1]]></source_system_user_password>\
	<target_password><![CDATA[$SYSTEM_ADMIN_PWD]]></target_password>\
	<target_system_user_password><![CDATA[HXEHana1]]></target_system_user_password>\
</Passwords>" | sudo /hana/shared/${SID}/hdblcm/hdblcm --action=rename_system -H localhost=${HOST_NAME}.${DOMAIN_NAME} --nostart --skip_hostagent_calls --certificates_hostmap=${HOST_NAME}.${DOMAIN_NAME}=${HOST_NAME}.${DOMAIN_NAME} --read_password_from_stdin=xml -b ${xsa_args}
		if [ $? -ne 0 ]; then
			exit 1
		fi

		# Reset user profile
		chmod 755 ${HOME}/.profile
		sed -i 's|^if \[ -f \$HOME/\.bashrc.*|if \[ -f \$HOME/.bashrc -a -z "\$SAPSYSTEMNAME" \]; then|' ${HOME}/.profile
		chmod 755 ${HOME}/.bashrc
		echo '[[ $- == *m* ]] && $HOME/.init_boot_cfg.sh' >> ${HOME}/.bashrc

		# Re-source environment variables
		export SAP_RETRIEVAL_PATH=/usr/sap/HXE/HDB90/${HOST_NAME}.${DOMAIN_NAME}
		. $HOME/.sapenv.sh
	fi

	# Change hardware key
	echo "Please wait..."
	echo "Change hardware key..." >> $LOG_FILE
	sed -i '/^id = /d' /usr/sap/${SID}/SYS/global/hdb/custom/config/nameserver.ini
	/usr/sap/${SID}/HDB${INSTANCE}/exe/hdbnsutil -convertTopology >> $LOG_FILE 2>&1
	if [ $? -ne 0 ]; then
		echo "Failed to change hardware key.  See $LOG_FILE for detail."
		exit 1
	fi

	if [ $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
		sed -i -e 's/Autostart=0/Autostart=1/g' /usr/sap/${SID}/SYS/profile/${SID}_HDB${INSTANCE}_${HOST_NAME}.${DOMAIN_NAME}
	else
		sed -i -e 's/Autostart=0/Autostart=1/g' /usr/sap/${SID}/SYS/profile/${SID}_HDB${INSTANCE}_${HOST_NAME}
	fi
}

#
# Check local OS user password
# $1 - user/login name
# $2 - password
checkLocalOSUserPwd() {
	local user=$1
	local passwd=$2

	local shadow_hash=$(sudo grep "^$user" /etc/shadow | cut -d':' -f2)
	if [ -n "$shadow_hash" ]; then
		if [[ ! "$shadow_hash" =~ \* && ! "$shadow_hash" =~ \! ]]; then
			local algo=$(echo $shadow_hash | cut -d'$' -f2)
			local salt=$(echo $shadow_hash | cut -d'$' -f3)
			local allsalt="\$${algo}\$${salt}\$"
			local genpass=`python <<EOF
import crypt,sys
print crypt.crypt("$passwd", "$allsalt")
EOF`
			if [ "$genpass" == "$shadow_hash" ]; then
				return 0
			else
				echo "Invalid password."
				echo
			fi
		else
			return 0
		fi
	else
		echo
		echo "User \"$user\" does not exist."
		echo
	fi
	return 1
}

getInstallType() {
	if grep "^INSTALL_TYPE.*=.*OVA$" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt >& /dev/null; then
		INSTALL_TYPE="OVA"
	elif grep "^INSTALL_TYPE.*=.*OVA$" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt >& /dev/null; then
		INSTALL_TYPE="Docker"
	elif grep "^INSTALL_TYPE.*=.*OVA$" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt >& /dev/null; then
		INSTALL_TYPE="Binary"
	fi
}

getHostDomainName() {
	if hostname >& /dev/null; then
		HOST_NAME=`hostname | cut -d'.' -f1`
	fi

	if hostname -d >& /dev/null; then
		DOMAIN_NAME=`hostname -d`
	fi
}

#
# Wait for apps to start
#
waitAppsStarted() {
	if [ $HAS_XSA -ne 1 ]; then
		return
	fi

	echo "Login to XSA services..."
	xs login -u xsa_admin -p ${MASTER_PWD} -s SAP
	if [ $? -ne 0 ]; then
		echo
		echo "Cannot login to XSA services.  Please check HANA has started and login/password are correct."
		exit 1
	fi

	echo "Check/Wait for all apps to start.  This may take a while..."
	xs wait-for-apps --timeout 3600 --all-instances --space SAP
	if [ $? -ne 0 ]; then
		echo
		echo "Waiting for apps to start has timeout."
		exit 1
	fi
}

startTenantDB() {
	if [ $IS_TENANT_STARTED -ne 1 ]; then
		echo "Start \"HXE\" tenant database..."
		hdbsql -i ${INSTANCE} -d SystemDB -u SYSTEM -p ${MASTER_PWD} "ALTER SYSTEM START DATABASE HXE"
		IS_TENANT_STARTED=1
	fi
}

stopTenantDB() {
	if [ $IS_TENANT_STARTED -eq 1 ]; then
		echo "Stop \"HXE\" tenant database..."
		hdbsql -i ${INSTANCE} -d SystemDB -u SYSTEM -p ${MASTER_PWD} "ALTER SYSTEM STOP DATABASE HXE"
		IS_TENANT_STARTED=0
	fi
}

#
# Do garbage collection
#
collectGarbage() {
	/usr/sap/${SID}/home/bin/hxe_gc.sh<<-EOF
${MASTER_PWD}
EOF
}



#########################################################
# Main
#########################################################

INSTALL_TYPE=""
HXE_DIR="HANA_EXPRESS_20"
SID="HXE"
INSTANCE="90"
HAS_SERVER=0
HAS_XSA=0
IS_TENANT_STARTED=0
SYSTEM_ADMIN_USER="hxeadm"
SYSTEM_ADMIN_PWD=""
OLD_MASTER_PWD="HXEHana1"
MASTER_PWD=""
SETUP_PROXY=1
SYSTEM_PROXY_HOST=""
SYSTEM_PROXY_PORT=""
SYSTEM_NO_PROXY_HOST=""
PROXY_HOST=""
PROXY_PORT=""
NO_PROXY_HOST=""
HOST_NAME="hxehost"
DOMAIN_NAME="localdomain"
IS_HOST_DOMAIN_CHANGE=0
WAIT_XSA_CONFIG=1
CONFIG_XSA_PID=-1

DATE=$(date +"%Y-%m-%d_%H.%M.%S")
LOG_FILE="/var/tmp/hdb_init_config_${DATE}.log"

if [ ! -f "${HOME}/.init_boot" ]; then
	exit 0
else
	. "${HOME}/.init_boot"
fi

if [ -d "/hana/shared/${SID}/xs/router" ]; then
	HAS_XSA=1
fi

# Capture output to log
if [ -f $LOG_FILE ]; then
	rm -f $LOG_FILE
fi
touch $LOG_FILE
chmod 640 $LOG_FILE
date +"%Y-%m-%d %H.%M.%S :" >> $LOG_FILE
echo "" >> $LOG_FILE

echo
echo "##############################################################################"
echo "# Welcome to SAP HANA, express edition 2.0.                                  #"
echo "#                                                                            #"
echo "# The system must be configured before use.                                  #"
echo "##############################################################################"
echo


getInstallType
getHostDomainName

#if [ "$INSTALL_TYPE" == "OVA" ]; then
#	promptHostName
#	promptDomainName
#
#	if [ "${HOST_NAME}.${DOMAIN_NAME}" != "hxehost.localdomain" ]; then
#		IS_HOST_DOMAIN_CHANGE=1
#	fi
#
#	promptPwd "System administrator (${SYSTEM_ADMIN_USER})" "SYSTEM_ADMIN_PWD"
#	while ! checkLocalOSUserPwd  ${SYSTEM_ADMIN_USER} ${SYSTEM_ADMIN_PWD}; do
#		promptPwd "System administrator (${SYSTEM_ADMIN_USER})" "SYSTEM_ADMIN_PWD"
#	done
#fi

promptNewPwd "HANA database master" "MASTER_PWD"

promptProxyInfo

promptWaitXSAConfig

printSummary >& >(tee -a "$LOG_FILE")

# Capture setup output to log file
exec 0>&-
exec >& >( awk -v lfile="$LOG_FILE" '{ print $0; print strftime("%Y-%m-%d %H:%M:%S :"),$0 >> (lfile); fflush() }' )

if [ "$INSTALL_TYPE" == "OVA" ]; then
	changeHostName
	convertTopology
fi

checkServer

changePwd

changeKey

collectGarbage

if [ $HAS_XSA -eq 0 ]; then
	install_date=`date --utc`
	sed -i "s/^INSTALL_DATE.*=.*/INSTALL_DATE=$install_date/" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt

	echo
	echo
	echo "*** Congratulations! SAP HANA, express edition 2.0 is configured. ***"
	if [ "$INSTALL_TYPE" == "OVA" -a $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
		echo "*** Please reboot system to take affect. ***"
	fi
	echo

	rm -f "${HOME}/.init_boot"
else
	if [ $WAIT_XSA_CONFIG -eq 1 ]; then
		configXSA

		install_date=`date --utc`
		sed -i "s/^INSTALL_DATE.*=.*/INSTALL_DATE=$install_date/" /usr/sap/${SID}/SYS/global/hdb/hxe_info.txt
		echo
		echo
		echo "*** Congratulations! SAP HANA, express edition 2.0 is configured. ***"
		if [ "$INSTALL_TYPE" == "OVA" -a $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
			echo "*** Please reboot system to take affect. ***"
		fi
		echo

		rm -f "${HOME}/.init_boot"

	else
		configXSAInBackground &
		CONFIG_XSA_PID=$!
		echo
		echo
		echo "*** SAP HANA, express edition 2.0 server is ready for use. ***"
		echo "*** XSA configuration continues in background.  The process ID is $CONFIG_XSA_PID. ***"
		echo "*** See /usr/sap/${SID}/home/xsa_config_status for status. ***"
		if [ "$INSTALL_TYPE" == "OVA" -a $IS_HOST_DOMAIN_CHANGE -eq 1 ]; then
			echo "*** When XSA configuration complete, reboot system to take affect. **"
		fi
		echo
	fi
fi
