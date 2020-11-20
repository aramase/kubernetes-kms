FROM alpine:3.5
WORKDIR /bin

ADD _output/kubernetes-kms /bin/k8s-azure-kms

CMD ["./k8s-azure-kms"] 