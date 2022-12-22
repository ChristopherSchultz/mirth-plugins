#!/bin/sh

# You can set CURL_OPTS if you'd like.
DEFAULT_MIRTH_URL="http://localhost:8080/api"
DEFAULT_CONTENT_TYPE=text/plain
VERBOSE=0

usage() {
cat<<EOD
Usage: ${0} -c channelId [options] messagefile [...]

Options:
  -b url   Specify the base URL for the Mirth API (default: $DEFAULT_MIRTH_URL)
  -c guid  Specify the channel for the messages (required)
  -d id    Specify the channel destination for the messages
  -t mime  Specify the content type of the message files (default: $DEFAULT_CONTENT_TYPE)
  -v       Enable verbose logging
EOD
}

MIRTH_BASE_URL="${MIRTH_BASE_URL:-${DEFAULT_MIRTH_URL}}"
CONTENT_TYPE=${DEFAULT_CONTENT_TYPE}

while getopts "b:c:d:t:vh" o; do
  case "${o}" in
    b)
        MIRTH_BASE_URL="${OPTARG}"
        ;;
    c)
        MIRTH_CHANNEL="${OPTARG}"
        ;;
    d)
        MIRTH_DESTINATION="${OPTARG}"
        ;;
    t)
        CONTENT_TYPE="${OPTARG}"
        ;;
    v)
        VERBOSE=$( expr "$VERBOSE" + 1 )
        ;;
    h)
        usage
        exit 0
        ;;
    *)
        usage
        exit 1
  esac
done
shift $((OPTIND-1))

if [ "" = "$MIRTH_CHANNEL" ] ; then
  usage
  exit 1
fi

if [ 0 = $( expr "${MIRTH_CHANNEL}" : '^[a-fA-F0-9-]*$' ) ] ; then
  echo Invalid channel id: $MIRTH_CHANNEL
  exit 1
fi

if [ "" != "${MIRTH_DESTINATION}" ] ; then
  if [ 0 = $( expr "${MIRTH_DESTINATION}" : '^[a-fA-F0-9]*$' ) ] ; then
    echo "Invalid destination id: $MIRTH_DESTINATION"
    exit 1
  fi

  MIRTH_DESTINATION="?destinationMetaDataId=${MIRTH_DESTINATION}"
fi

MIRTH_URL="${MIRTH_BASE_URL}/channels/${MIRTH_CHANNEL}/messages${MIRTH_DESTINATION}"

if [ 0 -lt "$VERBOSE" ] ; then
  echo Sending messages to Mirth: $MIRTH_URL
fi

for message in "$@" ; do
  if [ 0 -lt "$VERBOSE" ] ; then
    echo Sending $message
  fi

  if [ 1 -lt "$VERBOSE" ] ; then
    echo curl --header 'X-Requested-With: OpenAPI' \
         --header 'Accept: text/html,application/json,application/xml,text/xml,*' \
         --header "Content-Type: $CONTENT_TYPE" \
         --data "@${message}" \
         $CURL_OPTS \
         "${MIRTH_URL}"
  fi

  response=$( curl --header 'X-Requested-With: OpenAPI' \
       --header 'Accept: text/html,application/json,application/xml,text/xml,*' \
       --header "Content-Type: $CONTENT_TYPE" \
       --data "@${message}" \
       --silent --show-error \
       $CURL_OPTS \
       "${MIRTH_URL}" )

  result=$?

  if [ 1 -lt "$VERBOSE" ] ; then
    echo curl result: $result
    echo "HTTP response:"
    echo "$response"
  fi
done
