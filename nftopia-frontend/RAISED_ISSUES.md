# RAISED UI ISSUES

1. Inconsistent button styles and usage across the application (multiple custom and native <button> elements, custom classes, and at least two different button components: Button and StyledButton).
2. Lack of unified button variants and states (primary, secondary, danger, icon, loading, etc.) in several UI areas.
3. Accessibility inconsistencies in button implementations (missing ARIA attributes, inconsistent focus/hover/active/disabled states).
4. Some buttons do not use the reusable Button component, leading to duplicated logic and inconsistent user experience.
5. Button color, size, and border radius are not standardized across all modals, forms, and toolbars.
6. Incomplete documentation and migration guide for button usage and best practices.
7. Modal components (e.g., WalletModal) lack consistent styling, accessibility, and focus management.
8. Dropdown components (e.g., LanguageSwitcher, WalletConnector, UserDropdown) have inconsistent open/close logic and accessibility support.
9. Theme switching (light/dark mode) is not consistently applied or visually validated across all UI components.
10. Input components (e.g., Input) lack consistent styling, validation feedback, and accessibility support across forms.

11. Inconsistent table/list/grid presentation and lack of empty state handling.
12. Missing or inconsistent user avatar/profile image handling across components.
13. Notification/toast/alert components lack unified styling and placement.
14. Stepper/wizard/onboarding flows are not standardized or visually consistent.
15. Incomplete or inconsistent localization/i18n support for all UI strings.
16. Lack of clear error boundaries and fallback UIs for network or runtime errors.
17. No unified loading/spinner/skeleton state management for async content.
18. Inconsistent or missing pagination and filtering in data-heavy views.
19. Accessibility gaps in keyboard navigation, focus management, and ARIA roles.
20. Inconsistent use of icons, SVGs, and image assets (e.g., missing alt text, sizing issues).
