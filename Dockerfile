FROM amazon/aws-lambda-python:3.8

RUN set -ex && \
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm && \
    yum -y install clamav clamav-update && \
    /bin/echo -e "DatabaseMirror database.clamav.net\nCompressLocalDatabase yes" > /etc/freshclam.conf
COPY requirements.txt ./requirements.txt
RUN pip install -r requirements.txt
COPY ./*.py ./
CMD ["scan.lambda_handler"]

