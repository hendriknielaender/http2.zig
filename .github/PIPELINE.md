# CI/CD Pipeline Documentation

This document describes the CI/CD pipeline implemented for the HTTP/2.zig library.

## 🚀 Pipeline Overview

Our CI/CD pipeline consists of focused workflows designed to ensure code quality and reliability:

### 1. **CI Pipeline** (`ci.yml`)
**Triggers:** Push to `main`/`develop`, Pull Requests
**Purpose:** Core continuous integration checks

#### Jobs:
- **Lint & Format**: Code formatting checks with `zig fmt`
- **Multi-platform Tests**: Unit tests on Ubuntu, macOS, Windows (Debug & Release)
- **Documentation**: Auto-generate and deploy docs to GitHub Pages

#### Features:
- ✅ Multi-platform support (Linux, macOS, Windows)
- ✅ Dual build modes (Debug for development, Release for performance)
- ✅ Cached builds for faster execution
- ✅ BoringSSL dependency management
- ✅ Automated documentation deployment

### 2. **HTTP/2 Conformance Testing** (`h2spec.yml`)
**Triggers:** Push, Pull Requests
**Purpose:** RFC compliance validation using h2spec

#### Jobs:
- **H2spec Conformance**: Comprehensive HTTP/2 protocol testing
- **TLS & Plaintext**: Tests both encrypted and plain connections
- **Results Analysis**: Automated parsing and reporting of test results
- **Badge Generation**: Dynamic conformance badges for README

#### Features:
- ✅ Automated certificate generation
- ✅ JSON result parsing and analysis
- ✅ PR commenting with test results
- ✅ Conformance rate calculation
- ✅ Historical result tracking

### 3. **Release Pipeline** (`release.yml`)
**Triggers:** Version tags (`v*.*.*`), Manual dispatch
**Purpose:** Automated release creation and distribution

#### Jobs:
- **Validation**: Version format and pre-checks
- **Multi-platform Build**: Artifacts for Linux, macOS, Windows
- **Changelog Generation**: Automated changelog from git history
- **GitHub Release**: Release creation with assets and checksums
- **Package Publishing**: Preparation for package registries

#### Features:
- ✅ Semantic versioning validation
- ✅ Cross-platform artifact generation
- ✅ SHA256 checksums for security
- ✅ Automated changelog generation
- ✅ Pre-release support
- ✅ Draft release option


## 🔧 Configuration

### Environment Variables
```yaml
ZIG_VERSION: "0.14.0"           # Zig compiler version
CACHE_VERSION: "v1"             # Cache key versioning
H2SPEC_VERSION: "2.6.0"         # h2spec version
SERVER_PORT: 9001               # Default server port
TIMEOUT_DURATION: 300           # Test timeout (seconds)
```

### Secrets Required
- `GITHUB_TOKEN`: Automatically provided by GitHub

### Branch Protection
Recommended branch protection rules for `main`:

```yaml
Required status checks:
  - CI Pipeline / Code Quality
  - CI Pipeline / Unit Tests (ubuntu-latest, release)
  - HTTP/2 Conformance Testing / HTTP/2 Conformance Tests (tls)

Restrictions:
  - Require pull request reviews before merging
  - Dismiss stale reviews when new commits are pushed
  - Require review from code owners
  - Restrict pushes that create files in .github/workflows/
```

## 📊 Monitoring & Reporting

### Artifacts Generated
1. **Test Results**: Test reports and coverage data
2. **Conformance Reports**: h2spec JSON results
3. **Build Artifacts**: Cross-platform binaries and libraries
4. **Documentation**: API docs and examples

### GitHub Pages Integration
- **Documentation**: Auto-deployed API docs
- **Conformance Results**: Historical h2spec results

### Notifications
- **PR Comments**: Automated test result summaries
- **Badge Updates**: Dynamic README badges

## 🛠 Development Workflow

### For Contributors
1. **Fork & Clone**: Standard GitHub workflow
2. **Feature Branch**: Create feature branch from `develop`
3. **Development**: Write code with tests
4. **Local Testing**: Run `zig build test` locally
5. **Format Check**: Run `zig fmt src/ examples/`
6. **Pull Request**: Create PR to `develop` branch
7. **CI Validation**: Wait for all checks to pass
8. **Review**: Address review feedback
9. **Merge**: Squash merge to `develop`

### For Maintainers
1. **Release Preparation**: 
   - Merge `develop` → `main`
   - Update version in `build.zig.zon`
   - Create release notes
2. **Release Creation**: 
   - Create and push version tag: `git tag v1.0.0`
   - Release pipeline automatically triggers
3. **Post-Release**:
   - Verify release artifacts
   - Update documentation
   - Announce release

## 🔍 Troubleshooting

### Common Issues

#### Build Failures
- **BoringSSL Build Issues**: Ensure submodules are properly initialized
- **Platform Differences**: Check platform-specific dependencies
- **Cache Issues**: Clear cache by updating `CACHE_VERSION`

#### Test Failures
- **Flaky Tests**: Check for timing issues or resource constraints
- **Platform-Specific**: Review test logic for platform assumptions
- **Memory Issues**: Use Valgrind locally for debugging


### Debug Commands
```bash
# Local development
zig build test --summary all              # Run all tests
zig fmt --check src/ examples/            # Check formatting
zig build -Drelease=false                 # Debug build

# Conformance testing
h2spec --host localhost --port 9001 --tls --insecure
```

## 📈 Metrics & KPIs

### Code Quality
- **Test Coverage**: Aim for >90%
- **Build Success Rate**: Target >95%
- **Code Formatting**: 100% compliance


### Compliance
- **h2spec Pass Rate**: Target >95%
- **RFC Compliance**: Track specific test failures
- **Protocol Support**: HTTP/2 feature completeness

## 🚀 Future Enhancements

### Planned Improvements
1. **Package Registry**: Automated publishing to Zig package manager
2. **Integration Tests**: End-to-end testing with real applications
3. **Performance Baselines**: Automated performance regression detection
4. **Multi-Architecture**: ARM64, RISC-V support
5. **Chaos Engineering**: Fault injection testing
6. **Coverage Reporting**: Detailed code coverage analysis

### Advanced Features
- **Canary Deployments**: Gradual rollout testing
- **A/B Testing**: Performance comparison testing
- **Compliance Reporting**: Automated compliance documentation
- **Security Scanning**: Integration with more security tools
- **Performance Profiling**: Continuous performance monitoring

---

For questions or improvements to this pipeline, please open an issue or submit a pull request.