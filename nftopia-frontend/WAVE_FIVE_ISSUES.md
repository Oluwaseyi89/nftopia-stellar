# WAVE FIVE FRONTEND ISSUES

1. Complete Email Login Submission Flow
Implement the email login path in the auth login page so form submission calls the real auth store action and returns actionable backend error messages instead of placeholder behavior.

2. Unify Frontend Auth Source of Truth
Consolidate AuthContext and auth-store usage into one canonical auth layer to eliminate placeholder methods, type casting workarounds, and inconsistent session state across pages.

3. Remove Duplicate Mock Logged-In Dashboard Route
Replace the auth logged-in mock dashboard page with real API-backed data or remove the route to avoid conflicting user experiences and stale stats.

4. Replace Popular Collection Mock Data with Real Featured Feed
Swap hardcoded collections in the popular collections component for backend-driven data with loading and empty states so homepage interactions reflect real marketplace activity.

5. Persist Collection Likes to Backend
Implement a real like/unlike API flow for collection cards so engagement interactions persist across refreshes and users.

6. Complete WalletConnect Provider Integration
Replace WalletConnect placeholder messaging with a functional Stellar-compatible provider flow including connect, reconnect, and error fallback handling.

7. Enforce Locale-Aware Navigation Across All Auth and Creator Links
Audit and fix route pushes and hrefs to consistently include active locale prefixes so users are never redirected to wrong-language paths.

8. Add Global API Error and Retry UX Layer
Introduce a shared error handling pattern for network failures, timeouts, and backend validation responses so users get consistent retry options instead of silent failures.

9. Harden Session Expiry and Token Refresh UX
Implement predictable token-refresh and session-expiry handling to prevent random logouts, stale UI state, and failed actions during long user sessions.

10. Standardize Form Validation and Server Error Mapping
Unify client-side validation rules and backend error mapping across auth and creator forms so users receive clear field-level guidance before and after submission.

11. Build End-to-End Tests for Critical User Journeys
Add E2E coverage for register, login, wallet connect, browse, create, and logout flows so interaction regressions are caught before release.

12. Improve Wallet Modal and Dropdown Accessibility
Ensure wallet and account interaction components have complete keyboard navigation, focus management, ARIA labels, and escape behavior for assistive technology users.

13. Add Reliable Image Fallback and Progressive Loading Strategy
Implement image fallback handling, skeleton placeholders, and optimized loading for cards and avatars to avoid broken visuals during slow or failed media fetches.

14. Add Interaction Telemetry for Frontend Product Decisions
Instrument key interaction events such as connect wallet, submit forms, and CTA clicks so the team can measure friction points and prioritize UX fixes with data.

15. Improve Mobile Interaction Polish for Marketplace Actions
Refine tap targets, sticky actions, and responsive state transitions on mobile screens to reduce accidental taps and improve completion rates for core flows.
