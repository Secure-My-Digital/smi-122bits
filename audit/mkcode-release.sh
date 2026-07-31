#

json_xs -t yaml -f yaml -e '$_ = $_->{publish}{files}' < ../deploy.yml | tail +2 | cut -d' ' -f2 | sed -e 's,^,../,' | tee list.lof
cat list.lof | mkjson.pl -t code-release.json
ls -l code-release.json


