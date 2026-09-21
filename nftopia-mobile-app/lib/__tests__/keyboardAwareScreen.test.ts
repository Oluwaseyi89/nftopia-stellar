// Written without JSX so it matches the project's jest testMatch (*.test.ts).
// ── Mocks (hoisted) ──────────────────────────────────────────────────────────
const mockUseSafeAreaInsets = jest.fn(() => ({
  top: 44,
  right: 0,
  bottom: 34,
  left: 0,
}));

jest.mock('react-native-safe-area-context', () => ({
  useSafeAreaInsets: () => mockUseSafeAreaInsets(),
}));

jest.mock('react-native', () => {
  const React = require('react');
  // Small stand-ins for the RN primitives used by KeyboardAwareScreen so the
  // wrapper can be rendered with react-test-renderer in a node test env.
  const mock = (name: string) =>
    function MockedOutput(props: Record<string, unknown>) {
      return React.createElement(
        'RCTMocked',
        { ...props, __component: name },
        (props as { children?: unknown }).children
      );
    };
  return {
    Platform: { OS: 'ios' },
    StyleSheet: {
      create: (obj: Record<string, unknown>) => obj,
      flatten: (x: unknown) => x,
    },
    View: mock('View'),
    ScrollView: mock('ScrollView'),
    KeyboardAvoidingView: mock('KeyboardAvoidingView'),
    TouchableWithoutFeedback: mock('TouchableWithoutFeedback'),
    Keyboard: { dismiss: jest.fn() },
  };
});

// ── Imports (after mocks) ─────────────────────────────────────────────────────
import React from 'react';
import * as TestRenderer from 'react-test-renderer';
import { KeyboardAwareScreen, getKeyboardBehavior } from '@/src/components/KeyboardAwareScreen';

describe('getKeyboardBehavior', () => {
  it('uses padding behavior on iOS so content lifts above the keyboard', () => {
    expect(getKeyboardBehavior('ios')).toBe('padding');
  });

  it('uses no explicit behavior on Android (adjustResize handles resizing)', () => {
    expect(getKeyboardBehavior('android')).toBeUndefined();
  });
});

describe('KeyboardAwareScreen', () => {
  beforeEach(() => {
    mockUseSafeAreaInsets.mockReturnValue({ top: 44, right: 0, bottom: 34, left: 0 });
  });

  const byComponent = (name: string) => (n: TestRenderer.ReactTestInstance) =>
    n.props.__component === name;

  function render(screen: React.ReactElement<any>): TestRenderer.ReactTestRenderer {
    let renderer!: TestRenderer.ReactTestRenderer;
    TestRenderer.act(() => {
      renderer = TestRenderer.create(screen as any);
    });
    return renderer;
  }

  it('renders a KeyboardAvoidingView with platform padding behavior', () => {
    const root = render(
      React.createElement(KeyboardAwareScreen, {
        children: React.createElement(React.Fragment),
      })
    ).root;
    const avoiding = root.findAll(byComponent('KeyboardAvoidingView'));
    expect(avoiding).toHaveLength(1);
    expect(avoiding[0].props.behavior).toBe('padding');
  });

  it('wraps the body in a scrollable ScrollView with the keyboard handled', () => {
    const root = render(
      React.createElement(KeyboardAwareScreen, {
        children: React.createElement(React.Fragment),
      })
    ).root;
    const scroll = root.findAll(byComponent('ScrollView'));
    expect(scroll).toHaveLength(1);
    expect(scroll[0].props.keyboardShouldPersistTaps).toBe('handled');

    // Tapping outside dismisses the keyboard via the wrapping touchable.
    const touchable = root.findAll(byComponent('TouchableWithoutFeedback'));
    expect(touchable).toHaveLength(1);
    expect(typeof touchable[0].props.onPress).toBe('function');
  });

  it('keeps the footer in the tree and applies safe-area bottom padding', () => {
    const root = render(
      React.createElement(KeyboardAwareScreen, {
        footer: React.createElement(React.Fragment),
        children: React.createElement(React.Fragment),
      })
    ).root;

    const hasBottomPadding = (style: unknown): boolean => {
      const list = Array.isArray(style) ? style : [style];
      return list.some(
        (s) =>
          s &&
          typeof s === 'object' &&
          (s as { paddingBottom?: number }).paddingBottom === 34
      );
    };

    const footer = root.findAll(
      (n) => n.props.__component === 'View' && hasBottomPadding(n.props.style)
    );
    expect(footer).toHaveLength(1);
  });

  it('honours the keyboardDismissMode prop on the ScrollView', () => {
    const root = render(
      React.createElement(KeyboardAwareScreen, {
        keyboardDismissMode: 'on-drag',
        children: React.createElement(React.Fragment),
      })
    ).root;
    const scroll = root.findAll(byComponent('ScrollView'));
    expect(scroll[0].props.keyboardDismissMode).toBe('on-drag');
  });
});
