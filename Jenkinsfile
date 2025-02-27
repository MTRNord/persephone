pipeline {
    agent {
        kubernetes {
            yaml """
            apiVersion: v1
            kind: Pod
            spec:
              containers:
              - name: fedora
                image: fedora:41
                command:
                - cat
                tty: true
                securityContext:
                  privileged: true
            """
        }
    }

    environment {
        DOCKER_BUILDKIT = '1'
        SERVER_NAME = 'localhost'
    }

    stages {
        stage('Set Pending Status') {
            steps {
                container('fedora') {
                    script {
                        setBuildStatus("Build started", "PENDING")
                    }
                }
            }
        }

        stage('Checkout') {
            steps {
                container('fedora') {
                    checkout scm
                }
            }
        }

        stage('Install Podman') {
            steps {
                container('fedora') {
                    sh '''
                    dnf install -y podman
                    '''
                }
            }
        }

        stage('Build and Test') {
            parallel {
                stage('Build and Test Persephone') {
                    stages {
                        stage('Install Dependencies') {
                            steps {
                                container('fedora') {
                                    sh '''
                                    dnf install -y libevent-devel lcov libicu-devel libasan libubsan libsodium-devel libpq-devel jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang
                                    sed -i 's%includedir=/usr/include/ldns/ldns%includedir=/usr/include/ldns%g' /usr/lib64/pkgconfig/ldns.pc
                                    '''
                                }
                            }
                        }

                        stage('Build Drogon') {
                            steps {
                                container('fedora') {
                                    sh '''
                                    cd /tmp
                                    git clone https://github.com/drogonframework/drogon
                                    cd drogon
                                    git submodule update --init
                                    mkdir build
                                    cd build
                                    cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_EXAMPLES=OFF -DBUILD_CTL=OFF -DBUILD_POSTGRESQL=ON -DBUILD_REDIS=OFF -DBUILD_SQLITE=OFF -DBUILD_MYSQL=OFF -DBUILD_ORM=ON -DBUILD_SHARED_LIBS=ON ..
                                    make
                                    make install
                                    ln -s /usr/local/lib/libdrogon.so.1 /usr/lib/libdrogon.so.1
                                    ln -s /usr/local/lib/libtrantor.so.1 /usr/lib/libtrantor.so.1
                                    '''
                                }
                            }
                        }

                        stage('Build and Test') {
                            steps {
                                container('fedora') {
                                    sh '''
                                    CC=/usr/bin/gcc CXX=/usr/bin/g++ cmake -S . -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DDISABLE_TESTS=OFF -DCODE_COVERAGE=ON
                                    cp ./.lcovrc ~/.lcovrc
                                    cd cmake-build-debug
                                    make ccov-all
                                    cd ..
                                    '''
                                }
                            }
                        }

                        stage('Publish Coverage') {
                            steps {
                                container('fedora') {
                                    publishHTML(target: [
                                        reportDir: 'cmake-build-debug/ccov/all-merged',
                                        reportFiles: 'index.html',
                                        reportName: 'Code Coverage Report',
                                        keepAll: true,
                                    ])
                                }
                            }
                        }
                    }
                }

                /*stage('Build Container Image') {
                    steps {
                        container('fedora') {
                            sh '''
                            dnf install -y podman
                            '''
                            script {
                                def podmanImage = sh(script: "podman build -t mtrnord/persephone:${env.BUILD_ID} .", returnStdout: true).trim()
                                //sh "podman push ${podmanImage}"
                            }
                        }
                    }
                }*/

                stage('Run Complement Tests') {
                    steps {
                        container('fedora') {
                            catchError(buildResult: 'SUCCESS', stageResult: 'FAILURE') {
                                sh '''
                                podman build -t complement-persephone -f complement/Dockerfile .
                                podman run --rm complement-persephone:latest
                                '''
                            }
                        }
                    }
                }
            }
        }

        stage('Package with CPack') {
            steps {
                container('fedora') {
                    sh '''
                    CC=/usr/bin/gcc CXX=/usr/bin/g++ cmake -S . -B cmake-build-release -DCMAKE_BUILD_TYPE=Release
                    cd cmake-build-release
                    ninja package
                    '''
                }
            }
        }

        stage('Publish Artifacts') {
            steps {
                container('fedora') {
                    archiveArtifacts artifacts: 'cmake-build-release/persephone-*.deb, cmake-build-release/persephone-*.rpm, cmake-build-release/persephone-*.tar.gz', allowEmptyArchive: true
                }
            }
        }
    }

    post {
        success {
            container('fedora') {
                script {
                    setBuildStatus("Build succeeded", "SUCCESS")
                }
            }
        }
        failure {
            container('fedora') {
                script {
                    setBuildStatus("Build failed", "FAILURE")
                }
            }
        }
    }
}

void setBuildStatus(String message, String state) {
    step([
        $class: "GitHubCommitStatusSetter",
        reposSource: [$class: "ManuallyEnteredRepositorySource", url: "https://github.com/MTRNord/persephone"],
        contextSource: [$class: "ManuallyEnteredCommitContextSource", context: "ci/jenkins/build-status"],
        errorHandlers: [[$class: "ChangingBuildStatusErrorHandler", result: "UNSTABLE"]],
        statusResultSource: [$class: "ConditionalStatusResultSource", results: [[$class: "AnyBuildResult", message: message, state: state]]]
    ])
}