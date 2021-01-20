@Library('dst-shared@master') _

dockerBuildPipeline {
        repository = "cray"
        imagePrefix = "cray"
        app = "trustedcerts-operator"
        name = "trustedcerts-operator"
        description = "HPE TrustedCerts K8S Operator"
        dockerfile = "Dockerfile"
        product = "shasta-standard,shasta-premium"
        githubPushRepo = "Cray-HPE/trustedcerts-operator"
        githubPushBranches = /(release\/.*|master)/
}
