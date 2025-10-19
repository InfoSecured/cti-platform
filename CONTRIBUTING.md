# Contributing to CTI Platform

Thanks for your interest in contributing! 🎉

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/InfoSecured/cti-platform.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Test thoroughly
6. Submit a pull request

## Code Style

- Use ES6+ JavaScript
- 2 spaces for indentation
- Descriptive variable names
- Comment complex logic
- Follow existing patterns

## Adding Integrations

When adding new threat intelligence sources:

1. Create integration class in `src/integrations/`
2. Add required secrets to documentation
3. Include error handling
4. Add rate limiting if needed
5. Update README.md with new integration

## Testing

Before submitting:
- Test locally with `wrangler dev`
- Verify all API endpoints work
- Check CORS headers
- Test error cases
- Ensure no secrets in code

## Pull Request Guidelines

- Clear description of changes
- Link related issues
- Include screenshots for UI changes
- Update documentation
- Pass all checks

## Security

- Never commit API keys or secrets
- Report vulnerabilities privately to maintainers
- Follow responsible disclosure

## Questions?

Open a [Discussion](https://github.com/InfoSecured/cti-platform/discussions) or reach out to maintainers.