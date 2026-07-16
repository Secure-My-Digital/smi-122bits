

![GitHub Streak](https://github-readme-streak-stats.herokuapp.com?user=michel47&theme=cobalt&date_format=j%20M%5B%20Y%5D&background=000000&border=7536B2&stroke=9243DD&ring=89502D&fire=FF9554&currStreakNum=D280FF&sideNums=BC52FF&currStreakLabel=64EAE2&sideLabels=48A8A2&dates=A42EE5)


# SMI Password Entropy Audit Package

This package provides the tools and documentation for third-party auditors to verify SMI's security claim that
all generated passwords contain at least 122 bits of Shannon entropy.

## Security Claim

**Claim:** All deterministically generated passwords in the SMI password manager contain at least 122 bits of Shannon entropy.

**Verification Method:** Statistical sampling with 6-sigma confidence bounds

**Confidence Level:** >99.999999% (6-sigma covers 99.999999% of normal distribution)

## Requirements

To access the protected Python script containing the algorithm details, auditors must decrypt the git-crypt protected files:

```bash
gpg --decrypt local.key.asc | git-crypt unlock -
```

> ask for the password

This will unlock the encrypted files and allow you to inspect the password generation algorithm implementation.

## Contact

For questions about this audit package, please contact:
- Security My Digital Team
- michel@securemy.digital

## Version History

- v1.0.0: Initial release for third-party audit

---

> *"Security is not a product, but a process. Entropy is not a feature, but a requirement."*, -- SMD Security Team [Security Manifesto, 2025]

\$Intent: Provide auditors with clear documentation and tools to verify SMD's 122-bit entropy security claim $

