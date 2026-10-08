import js from '@eslint/js'
import ts from 'typescript-eslint'
export default ts.config(js.configs.recommended,...ts.configs.recommended,{files:['src/**/*.{ts,tsx}'],rules:{'@typescript-eslint/no-explicit-any':'off'}})
