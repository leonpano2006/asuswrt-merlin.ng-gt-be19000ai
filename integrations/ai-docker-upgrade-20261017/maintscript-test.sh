set -eu
cd /home/leon-docker-upgrade-20261017
tar xzf /home/leon-docker-upload-7b05dd2ff0dcd378.tar.gz
python3 maintscript-test/test-maintainer-scripts.py
