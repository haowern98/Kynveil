import tseslint from 'typescript-eslint'

export default tseslint.config(
  { ignores: ['out/**', 'coverage/**', 'src/generated/**'] },
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname
      }
    }
  }
)
