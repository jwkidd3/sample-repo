pipeline {
  agent any
  options { timestamps() }
  environment { TARGET_URL = 'http://juice-shop:3000' }
  stages {
    stage('Checkout') { steps { checkout scm; sh 'ls -la' } }
    stage('SAST — Semgrep') {
      steps {
        sh '''docker run --rm -v $WORKSPACE:/src returntocorp/semgrep:latest \
              semgrep --config p/owasp-top-ten --json --output /src/semgrep-report.json /src \
              || echo "Semgrep done — continuing"'''
        archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
      }
    }
    stage('SCA — Trivy') {
      steps {
        sh '''docker run --rm -v $WORKSPACE:/src aquasec/trivy:latest \
              fs --severity HIGH,CRITICAL --format json --output /src/trivy-fs.json /src'''
        archiveArtifacts artifacts: 'trivy-fs.json', allowEmptyArchive: true
      }
    }
    stage('DAST — ZAP baseline') {
      steps {
        sh '''docker run --rm --network devsecops-lab \
              -v $WORKSPACE:/zap/wrk:rw ghcr.io/zaproxy/zaproxy:stable \
              zap-baseline.py -t $TARGET_URL -r zap-baseline.html -J zap-baseline.json -I'''
        archiveArtifacts artifacts: 'zap-baseline.html, zap-baseline.json', allowEmptyArchive: true
      }
    }
    stage('Critical gate') {
      steps {
        sh '''HIGH=$(jq '[.site[].alerts[] | select(.riskcode | tonumber >= 3)] | length' zap-baseline.json)
              ALLOW=${ALLOWED_HIGH:-0}
              echo "High-risk findings: $HIGH (allowed: $ALLOW)"
              [ "$HIGH" -gt "$ALLOW" ] && { echo "::: gate failed"; exit 1; } || true'''
      }
    }
  }
  post { always { publishHTML target: [reportDir: '.', reportFiles: 'zap-baseline.html', reportName: 'ZAP Baseline'] } }
}
