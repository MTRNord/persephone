pipeline {
    agent any

    environment {
        DOCKER_BUILDKIT = '1'
        SERVER_NAME = 'localhost'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Set Pending Status') {
            steps {
                script {
                    def commitSha = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                    githubCommitStatus context: 'Jenkins', status: 'PENDING', description: 'Build started', sha: commitSha
                }
            }
        }

        stage('Install Dependencies') {
            steps {
                sh '''
                sudo dnf install -y libevent-devel lcov libicu-devel libasan libubsan libsodium-devel libpq-devel jsoncpp-devel hiredis-devel ldns ldns-devel yaml-cpp yaml-cpp-devel uuid-devel zlib-devel clang-tools-extra ninja-build cmake git clang
                '''
            }
        }

        stage('Build and Test') {
            steps {
                sh '''
                CC=/usr/bin/clang-19 CXX=/usr/bin/clang++-19 cmake -S . -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug -DDISABLE_TESTS=OFF -DCMAKE_CXX_FLAGS_DEBUG="-g -O0 -Wall -fprofile-arcs -ftest-coverage" -DCMAKE_C_FLAGS_DEBUG="-g -O0 -Wall -W -fprofile-arcs -ftest-coverage" -DCMAKE_EXE_LINKER_FLAGS="-fprofile-arcs -ftest-coverage"
                cmake --build cmake-build-debug --config Debug
                ctest -T Test -T Coverage --rerun-failed --output-on-failure
                '''
            }
        }

        stage('Report Coverage') {
            steps {
                sh '''
                pushd cmake-build-debug
                lcov --directory ./CMakeFiles --capture --output-file coverage.info
                lcov --remove coverage.info -o coverage_filtered.info '*/_deps/*'
                popd
                '''
            }
        }

        stage('Build Docker Image') {
            steps {
                script {
                    def dockerImage = docker.build("mtrnord/persephone:${env.BUILD_ID}", "-f complement/Dockerfile .")
                    dockerImage.push()
                }
            }
        }

        stage('Run Complement Tests') {
            steps {
                sh '''
                docker build -t complement-persephone -f complement/Dockerfile .
                docker run --rm complement-persephone:latest
                '''
            }
        }
    }

    post {
        success {
            script {
                def commitSha = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                githubCommitStatus context: 'Jenkins', status: 'SUCCESS', description: 'Build succeeded', sha: commitSha
            }
        }
        failure {
            script {
                def commitSha = sh(script: 'git rev-parse HEAD', returnStdout: true).trim()
                githubCommitStatus context: 'Jenkins', status: 'FAILURE', description: 'Build failed', sha: commitSha
            }
        }
        always {
            archiveArtifacts artifacts: 'cmake-build-debug/coverage_filtered.info', allowEmptyArchive: true
            junit 'cmake-build-debug/**/*.xml'
        }
    }
}