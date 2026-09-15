import { describe, expect, it } from 'vitest';
import { render, screen } from '@testing-library/react';
import App from './App';

describe('EnChat app shell', () => {
  it('renders landing page content', () => {
    render(<App />);
    expect(screen.getByText('Private messaging. Nothing else.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument();
  });

  it('renders dashboard state after auth', () => {
    render(<App />);
    const button = screen.getByRole('button', { name: /create account/i });
    button.click();
    expect(screen.getByText('Create Account')).toBeInTheDocument();
  });
});
