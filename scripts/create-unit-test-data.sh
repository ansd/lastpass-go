#!/bin/bash

# This script uses the LastPass CLI to create unit test data.
#
# This script expects 2 LastPass account credentials as arguments.
# The 2nd account will share passwords with the 1st account.
#
# Prerequisites:
#
# The 2nd user needs to be a LastPass family user (since only they can create shared folders).
# The 2nd user needs to have added the 1st user as a family member.
# The 1st user needs to have accepted the family email invitation.
# (However, the 1st user doesn't need to be upgraded to a family account.)
#
# Before starting this script, make sure to be logged out the 1st user's account.

set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <user1> <password1> <user2> <password2>"
  exit 1
fi

read -p "I understand that all the secret data and passwords of the provided LastPass accounts
incuding their master passwords will be made publicly available.
I confirm that I have not stored any sensitive data in these LastPass accounts.
I will permanently delete these accounts after running this script. (y/n)?" choice
case "$choice" in
  y|Y )
    ;;
  n|N )
    echo "aborting"
    exit 1
    ;;
  * )
    echo "invalid input: enter y or n"
    exit 1
    ;;
esac

user1=$1
passwd1=$2
user2=$3
passwd2=$4


SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$SCRIPT_DIR"/../test/unit/

echo "$passwd2" | LPASS_DISABLE_PINENTRY=1 lpass login --force "$user2"

echo "creating shared folder with 1 ACCT"
lpass share create share1
sleep 6
lpass share useradd --read-only=false --hidden=false Shared-share1 "$user1"
sleep 6

cat<<EOF | lpass add --non-interactive --sync=now Shared-share1/nameShared0
URL: http://urlShared0
Username: userShared0
Password: passwordShared0
Notes:
notesShared0
EOF
sleep 6

id_nameshared0=$(lpass show --id Shared-share1/nameShared0)
echo "$id_nameshared0" > data/id-nameshared0.txt

echo "writing blob"
cd dumpblob
go build
cd ..
dump=$(./dumpblob/dumpblob "$user1" "$passwd1")
echo "$dump" | jq -j .PrivateKeyEncrypted > data/privatekeyencrypted.txt
echo "$dump" | jq -j .Blob > data/blob-sharingkeyrsaencrypted.txt

echo "creating shared folder with 2 ACCTs"
lpass share create share2
sleep 6
lpass share useradd --read-only=false --hidden=false Shared-share2 "$user1"
sleep 6

cat<<EOF | lpass add --non-interactive --sync=no Shared-share2/nameShared1
URL: http://urlShared1
Username: userShared1
Password: passwordShared1
Notes:
notesShared1
EOF
sleep 6
cat<<EOF | lpass add --non-interactive --sync=now Shared-share2/nameShared2
URL: http://urlShared2
Username: userShared2
Password: passwordShared2
Notes:
notesShared2
EOF
sleep 6

id_nameshared1=$(lpass show --id Shared-share2/nameShared1)
sleep 6
id_nameshared2=$(lpass show --id Shared-share2/nameShared2)
echo "$id_nameshared1" > data/id-nameshared1.txt
echo "$id_nameshared2" > data/id-nameshared2.txt
sleep 6
lpass logout --force

read -p "Now, use the browser plugin to log into the 1st user's account.
(This will AES encrypt the sharing key with the 1st user's encryption key.)
When done, press enter to continue."

echo "$passwd1" | LPASS_DISABLE_PINENTRY=1 lpass login --force "$user1"

echo "$user1" > data/user.txt
echo "$passwd1" > data/passwd.txt

sleep 6
echo "creating 1 ACCT"
cat<<EOF | lpass add --non-interactive --sync=now folder0/name0
URL: http://url0
Username: user0
Password: password0
Notes:
notes0
EOF
sleep 6

echo "writing blob"
./dumpblob/dumpblob "$user1" "$passwd1" | jq -j .Blob > data/blob-sharedaccounts.txt

echo "removing the 3 shared ACCTs"
lpass rm --sync=no "$id_nameshared0"
sleep 6
lpass rm --sync=no "$id_nameshared1"
sleep 6
lpass rm --sync=no "$id_nameshared2"
sleep 6

echo "creating 2 ACCTs"
cat<<EOF | lpass add --non-interactive --sync=no folder0/name1
URL: http://sn
Notes:
some secure note
EOF
sleep 6
cat<<EOF | lpass add --non-interactive --sync=now name2
URL: http://url2
EOF
sleep 6

id_name0=$(lpass show --id folder0/name0)
sleep 6
id_name1=$(lpass show --id name1)
sleep 6
id_name2=$(lpass show --id name2)
sleep 6
echo "$id_name0" > data/id-name0.txt
echo "$id_name1" > data/id-name1.txt
echo "$id_name2" > data/id-name2.txt

echo "writing blob"
./dumpblob/dumpblob "$user1" "$passwd1" | jq -j .Blob > data/blob-3accts.txt

echo "removing all 3 ACCTs"
lpass rm --sync=no "$id_name0"
sleep 6
lpass rm --sync=no "$id_name1"
sleep 6
lpass rm --sync=no "$id_name2"
sleep 6

echo "creating group account"
cat<<EOF | lpass add --non-interactive --sync=now "groupAccount/"
URL: http://group
Group: groupAccount
EOF
sleep 6

echo "writing blob"
./dumpblob/dumpblob "$user1" "$passwd1" | jq -j .Blob > data/blob-groupaccount.txt

echo "removing group account"
lpass rm --sync=now groupAccount/
sleep 6

echo "creating 1 ECB encrypted ACCT"
cd ecb
go build
cd ..
id_nameecb=$(./ecb/ecb "$user1" "$passwd1")
echo "$id_nameecb" > data/id-nameecb.txt

echo "writing blob"
./dumpblob/dumpblob "$user1" "$passwd1" | jq -j .Blob > data/blob-ecb.txt

echo "removing ECB account"
lpass rm --sync=now "$id_nameecb"
sleep 6

lpass logout -f
