//! Proc macros for constant-time cryptographic primitives.
//!
//! Provides `#[derive(CtEq)]`, `#[derive(CtSelect)]`, and `#[derive(CtSwap)]`
//! which generate constant-time trait implementations for structs containing
//! byte-array fields, preventing timing side-channel leakage.
//!
//! # Usage
//!
//! Users should depend on `simrs-consttime` (which re-exports the derives),
//! not on this crate directly.
//!
//! ```ignore
//! use simrs_consttime::{CtEq, CtSelect, CtSwap};
//!
//! #[derive(CtEq, CtSelect, CtSwap)]
//! struct Mac([u8; 8]);
//! ```
//!
//! # Supported Field Types
//!
//! All field types must implement the corresponding trait (`CtEq`, `CtSelect`,
//! `CtSwap`). Implementations are provided for `u8`, `u64`, `[u8; N]`, and
//! `[u64; N]` in the `simrs-consttime` crate.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index};

// ---------------------------------------------------------------------------
// CtEq
// ---------------------------------------------------------------------------

/// Core derive logic for `CtEq` using `proc_macro2` types for testability.
fn derive_ct_eq_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => generate_ct_eq_body(&data.fields),
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                name,
                "CtEq cannot be derived for enums (variant branching leaks timing)",
            )
            .to_compile_error();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(name, "CtEq cannot be derived for unions")
                .to_compile_error();
        }
    };

    quote! {
        impl #impl_generics simrs_consttime::CtEq for #name #ty_generics #where_clause {
            fn ct_eq(&self, other: &Self) -> simrs_consttime::CtBool {
                let mut all_eq = simrs_consttime::CtBool::TRUE;
                #body
                all_eq
            }
        }
    }
}

/// Generate the `CtEq` comparison body for struct fields.
///
/// Accumulates per-field `CtEq::ct_eq` results into an `all_eq: CtBool`
/// using `.and()`, avoiding any data-dependent branches.
fn generate_ct_eq_body(fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let field_checks = named.named.iter().map(|f| {
                let field_name = f.ident.as_ref().expect("named field must have ident");
                quote! {
                    all_eq = all_eq.and(
                        simrs_consttime::CtEq::ct_eq(&self.#field_name, &other.#field_name)
                    );
                }
            });
            quote! { #(#field_checks)* }
        }
        Fields::Unnamed(unnamed) => {
            let field_checks = unnamed.unnamed.iter().enumerate().map(|(i, _)| {
                let idx = Index::from(i);
                quote! {
                    all_eq = all_eq.and(
                        simrs_consttime::CtEq::ct_eq(&self.#idx, &other.#idx)
                    );
                }
            });
            quote! { #(#field_checks)* }
        }
        Fields::Unit => {
            // Unit structs are always equal -- all_eq stays TRUE.
            quote! {}
        }
    }
}

/// Derive macro for constant-time equality comparison.
///
/// Generates an implementation of `simrs_consttime::CtEq` that compares
/// all fields via their own `CtEq` implementations, accumulating results
/// with `CtBool::and()` without any data-dependent branches.
///
/// # Supported Structs
///
/// - Tuple structs: `struct Mac([u8; 8]);`
/// - Named structs: `struct Auth { mac: [u8; 8], res: [u8; 8] }`
/// - Unit structs: `struct Marker;` (trivially equal)
///
/// # Errors
///
/// Compile error if applied to an enum (variant branching leaks timing)
/// or a union.
#[proc_macro_derive(CtEq)]
pub fn derive_ct_eq(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    derive_ct_eq_impl(&input).into()
}

// ---------------------------------------------------------------------------
// CtSelect
// ---------------------------------------------------------------------------

/// Core derive logic for `CtSelect`.
fn derive_ct_select_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => generate_ct_select_body(name, &data.fields),
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                name,
                "CtSelect cannot be derived for enums (variant branching leaks timing)",
            )
            .to_compile_error();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(name, "CtSelect cannot be derived for unions")
                .to_compile_error();
        }
    };

    quote! {
        impl #impl_generics simrs_consttime::CtSelect for #name #ty_generics #where_clause {
            fn ct_select(
                cond: simrs_consttime::CtBool,
                a: &Self,
                b: &Self,
            ) -> Self {
                #body
            }
        }
    }
}

/// Generate the `CtSelect` body for struct fields.
fn generate_ct_select_body(name: &syn::Ident, fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let field_selects = named.named.iter().map(|f| {
                let field_name = f.ident.as_ref().expect("named field must have ident");
                quote! {
                    #field_name: simrs_consttime::CtSelect::ct_select(
                        cond, &a.#field_name, &b.#field_name
                    ),
                }
            });
            quote! {
                #name { #(#field_selects)* }
            }
        }
        Fields::Unnamed(unnamed) => {
            let field_selects = unnamed.unnamed.iter().enumerate().map(|(i, _)| {
                let idx = Index::from(i);
                quote! {
                    simrs_consttime::CtSelect::ct_select(cond, &a.#idx, &b.#idx),
                }
            });
            quote! {
                #name(#(#field_selects)*)
            }
        }
        Fields::Unit => {
            quote! { #name }
        }
    }
}

/// Derive macro for constant-time conditional select (cmov).
///
/// Generates an implementation of `simrs_consttime::CtSelect` that
/// performs per-field conditional selection.
#[proc_macro_derive(CtSelect)]
pub fn derive_ct_select(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    derive_ct_select_impl(&input).into()
}

// ---------------------------------------------------------------------------
// CtSwap
// ---------------------------------------------------------------------------

/// Core derive logic for `CtSwap`.
fn derive_ct_swap_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => generate_ct_swap_body(&data.fields),
        Data::Enum(_) => {
            return syn::Error::new_spanned(
                name,
                "CtSwap cannot be derived for enums (variant branching leaks timing)",
            )
            .to_compile_error();
        }
        Data::Union(_) => {
            return syn::Error::new_spanned(name, "CtSwap cannot be derived for unions")
                .to_compile_error();
        }
    };

    quote! {
        impl #impl_generics simrs_consttime::CtSwap for #name #ty_generics #where_clause {
            fn ct_swap(a: &mut Self, b: &mut Self, cond: simrs_consttime::CtBool) {
                #body
            }
        }
    }
}

/// Generate the `CtSwap` body for struct fields.
fn generate_ct_swap_body(fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let field_swaps = named.named.iter().map(|f| {
                let field_name = f.ident.as_ref().expect("named field must have ident");
                quote! {
                    simrs_consttime::CtSwap::ct_swap(
                        &mut a.#field_name, &mut b.#field_name, cond
                    );
                }
            });
            quote! { #(#field_swaps)* }
        }
        Fields::Unnamed(unnamed) => {
            let field_swaps = unnamed.unnamed.iter().enumerate().map(|(i, _)| {
                let idx = Index::from(i);
                quote! {
                    simrs_consttime::CtSwap::ct_swap(&mut a.#idx, &mut b.#idx, cond);
                }
            });
            quote! { #(#field_swaps)* }
        }
        Fields::Unit => {
            // Nothing to swap on unit structs.
            quote! {}
        }
    }
}

/// Derive macro for constant-time conditional swap (cswap).
///
/// Generates an implementation of `simrs_consttime::CtSwap` that
/// performs per-field conditional swap.
#[proc_macro_derive(CtSwap)]
pub fn derive_ct_swap(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    derive_ct_swap_impl(&input).into()
}

// ---------------------------------------------------------------------------
// Tests -- using proc_macro2 for unit testability
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- CtEq --

    /// Parse a token stream as a `DeriveInput` and run `derive_ct_eq_impl`.
    fn expand_ct_eq(input: TokenStream2) -> TokenStream2 {
        let parsed: DeriveInput = syn::parse2(input).expect("failed to parse input");
        derive_ct_eq_impl(&parsed)
    }

    #[test]
    fn ct_eq_tuple_struct_single_array() {
        let input = quote! {
            struct Mac([u8; 8]);
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(
            output_str.contains("impl simrs_consttime :: CtEq for Mac"),
            "output: {output_str}"
        );
        assert!(
            output_str.contains("simrs_consttime :: CtBool :: TRUE"),
            "output: {output_str}"
        );
        assert!(
            output_str.contains("simrs_consttime :: CtEq :: ct_eq"),
            "output: {output_str}"
        );
        assert!(output_str.contains("all_eq"), "output: {output_str}");
    }

    #[test]
    fn ct_eq_named_struct_multiple_fields() {
        let input = quote! {
            struct AuthResult {
                mac: [u8; 8],
                res: [u8; 16],
            }
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for AuthResult"));
        assert!(output_str.contains("self . mac"));
        assert!(output_str.contains("self . res"));
        // Both fields should use CtEq delegation
        assert!(output_str.contains("all_eq . and"), "output: {output_str}");
    }

    #[test]
    fn ct_eq_tuple_struct_u8_field() {
        let input = quote! {
            struct Byte(u8);
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for Byte"));
        assert!(
            output_str.contains("simrs_consttime :: CtEq :: ct_eq (& self . 0 , & other . 0)"),
            "output: {output_str}"
        );
    }

    #[test]
    fn ct_eq_unit_struct() {
        let input = quote! {
            struct Marker;
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for Marker"));
        // Unit struct body should be empty -- all_eq stays TRUE
        assert!(output_str.contains("all_eq"), "output: {output_str}");
    }

    #[test]
    fn ct_eq_enum_rejected() {
        let input = quote! {
            enum MyEnum {
                A,
                B,
            }
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(output_str.contains("compile_error"), "output: {output_str}");
        assert!(output_str.contains("enum"), "output: {output_str}");
    }

    #[test]
    fn ct_eq_mixed_u8_and_array_fields() {
        let input = quote! {
            struct Mixed {
                tag: u8,
                data: [u8; 16],
            }
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        assert!(output_str.contains("self . tag"), "output: {output_str}");
        assert!(output_str.contains("self . data"), "output: {output_str}");
    }

    #[test]
    fn ct_eq_no_branching_in_output() {
        let input = quote! {
            struct Nested {
                inner: SomeType,
            }
        };
        let output = expand_ct_eq(input);
        let output_str = output.to_string();

        // Must NOT contain `if` -- old implementation branched on nested CtEq
        assert!(
            !output_str.contains(" if "),
            "generated code branches: {output_str}"
        );
        // Must use CtBool AND accumulation
        assert!(output_str.contains("all_eq . and"), "output: {output_str}");
    }

    // -- CtSelect --

    fn expand_ct_select(input: TokenStream2) -> TokenStream2 {
        let parsed: DeriveInput = syn::parse2(input).expect("failed to parse input");
        derive_ct_select_impl(&parsed)
    }

    #[test]
    fn ct_select_tuple_struct() {
        let input = quote! {
            struct Mac([u8; 8]);
        };
        let output = expand_ct_select(input);
        let output_str = output.to_string();

        assert!(
            output_str.contains("impl simrs_consttime :: CtSelect for Mac"),
            "output: {output_str}"
        );
        assert!(
            output_str.contains("simrs_consttime :: CtSelect :: ct_select"),
            "output: {output_str}"
        );
    }

    #[test]
    fn ct_select_named_struct() {
        let input = quote! {
            struct Auth {
                mac: [u8; 8],
                res: [u8; 8],
            }
        };
        let output = expand_ct_select(input);
        let output_str = output.to_string();

        assert!(output_str.contains("a . mac"), "output: {output_str}");
        assert!(output_str.contains("b . res"), "output: {output_str}");
    }

    #[test]
    fn ct_select_enum_rejected() {
        let input = quote! {
            enum MyEnum { A, B }
        };
        let output = expand_ct_select(input);
        let output_str = output.to_string();

        assert!(output_str.contains("compile_error"), "output: {output_str}");
    }

    // -- CtSwap --

    fn expand_ct_swap(input: TokenStream2) -> TokenStream2 {
        let parsed: DeriveInput = syn::parse2(input).expect("failed to parse input");
        derive_ct_swap_impl(&parsed)
    }

    #[test]
    fn ct_swap_tuple_struct() {
        let input = quote! {
            struct Mac([u8; 8]);
        };
        let output = expand_ct_swap(input);
        let output_str = output.to_string();

        assert!(
            output_str.contains("impl simrs_consttime :: CtSwap for Mac"),
            "output: {output_str}"
        );
        assert!(
            output_str.contains("simrs_consttime :: CtSwap :: ct_swap"),
            "output: {output_str}"
        );
    }

    #[test]
    fn ct_swap_named_struct() {
        let input = quote! {
            struct Auth {
                mac: [u8; 8],
                res: [u8; 8],
            }
        };
        let output = expand_ct_swap(input);
        let output_str = output.to_string();

        assert!(output_str.contains("a . mac"), "output: {output_str}");
        assert!(output_str.contains("b . res"), "output: {output_str}");
    }

    #[test]
    fn ct_swap_unit_struct() {
        let input = quote! {
            struct Marker;
        };
        let output = expand_ct_swap(input);
        let output_str = output.to_string();

        assert!(
            output_str.contains("impl simrs_consttime :: CtSwap for Marker"),
            "output: {output_str}"
        );
        // Body should not contain CtSwap trait delegation (no fields to swap)
        assert!(
            !output_str.contains("simrs_consttime :: CtSwap :: ct_swap"),
            "output: {output_str}"
        );
    }

    #[test]
    fn ct_swap_enum_rejected() {
        let input = quote! {
            enum MyEnum { A, B }
        };
        let output = expand_ct_swap(input);
        let output_str = output.to_string();

        assert!(output_str.contains("compile_error"), "output: {output_str}");
    }
}
