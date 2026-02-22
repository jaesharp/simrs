//! Proc macros for constant-time cryptographic primitives.
//!
//! Provides `#[derive(CtEq)]` which generates a constant-time equality
//! comparison for structs containing byte-array fields, preventing timing
//! side-channel leakage.
//!
//! # Usage
//!
//! Users should depend on `simrs-consttime` (which re-exports the derive),
//! not on this crate directly.
//!
//! ```ignore
//! use simrs_consttime::CtEq;
//!
//! #[derive(CtEq)]
//! struct MacA([u8; 8]);
//! ```
//!
//! # Supported Field Types
//!
//! - `[u8; N]` -- byte arrays of any length
//! - `u8` -- single bytes
//! - Named and tuple struct layouts
//!
//! All fields must be byte-representable. The generated implementation
//! accumulates XOR differences across all bytes without early exit.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Index};

/// Core derive logic using `proc_macro2` types for testability.
///
/// Accepts a parsed `DeriveInput` and returns the generated `impl CtEq`
/// token stream. By operating on `proc_macro2::TokenStream`, this function
/// can be unit-tested without requiring the proc-macro runtime.
fn derive_ct_eq_impl(input: &DeriveInput) -> TokenStream2 {
    let name = &input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    let body = match &input.data {
        Data::Struct(data) => generate_struct_body(&data.fields),
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
            fn ct_eq(&self, other: &Self) -> bool {
                let mut diff = 0u8;
                #body
                diff == 0
            }
        }
    }
}

/// Generate the comparison body for struct fields.
///
/// For each field, generates code that XORs the bytes of `self.field` with
/// `other.field` and accumulates into `diff`.
fn generate_struct_body(fields: &Fields) -> TokenStream2 {
    match fields {
        Fields::Named(named) => {
            let field_checks = named.named.iter().map(|f| {
                let field_name = f.ident.as_ref().expect("named field must have ident");
                generate_field_check(
                    &quote! { self.#field_name },
                    &quote! { other.#field_name },
                    &f.ty,
                )
            });
            quote! { #(#field_checks)* }
        }
        Fields::Unnamed(unnamed) => {
            let field_checks = unnamed.unnamed.iter().enumerate().map(|(i, f)| {
                let idx = Index::from(i);
                generate_field_check(&quote! { self.#idx }, &quote! { other.#idx }, &f.ty)
            });
            quote! { #(#field_checks)* }
        }
        Fields::Unit => {
            // Unit structs are always equal.
            quote! {}
        }
    }
}

/// Generate constant-time comparison code for a single field.
///
/// Supports `[u8; N]` (byte arrays) and `u8` (single bytes).
fn generate_field_check(
    self_access: &TokenStream2,
    other_access: &TokenStream2,
    ty: &syn::Type,
) -> TokenStream2 {
    match ty {
        // [u8; N] -- iterate over bytes
        syn::Type::Array(arr) => {
            if is_u8_type(&arr.elem) {
                quote! {
                    {
                        let a = &#self_access;
                        let b = &#other_access;
                        let mut i = 0;
                        while i < a.len() {
                            diff |= a[i] ^ b[i];
                            i += 1;
                        }
                    }
                }
            } else {
                syn::Error::new_spanned(
                    arr,
                    "CtEq: only [u8; N] arrays are supported",
                )
                .to_compile_error()
            }
        }
        // u8 -- single byte
        syn::Type::Path(path) if is_u8_path(path) => {
            quote! {
                diff |= #self_access ^ #other_access;
            }
        }
        // Other types that implement CtEq -- delegate
        _ => {
            quote! {
                if !simrs_consttime::CtEq::ct_eq(&#self_access, &#other_access) {
                    diff |= 0xFF;
                }
            }
        }
    }
}

/// Check if a type is `u8`.
fn is_u8_type(ty: &syn::Type) -> bool {
    matches!(ty, syn::Type::Path(p) if is_u8_path(p))
}

/// Check if a type path is `u8`.
fn is_u8_path(path: &syn::TypePath) -> bool {
    path.qself.is_none()
        && path.path.segments.len() == 1
        && path.path.segments[0].ident == "u8"
        && path.path.segments[0].arguments.is_none()
}

/// Derive macro for constant-time equality comparison.
///
/// Generates an implementation of `simrs_consttime::CtEq` that compares
/// all fields byte-by-byte without early exit, preventing timing
/// side-channel attacks.
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
// Tests -- using proc_macro2 for unit testability
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse a token stream as a `DeriveInput` and run `derive_ct_eq_impl`.
    fn expand(input: TokenStream2) -> TokenStream2 {
        let parsed: DeriveInput = syn::parse2(input).expect("failed to parse input");
        derive_ct_eq_impl(&parsed)
    }

    #[test]
    fn tuple_struct_single_array() {
        let input = quote! {
            struct Mac([u8; 8]);
        };
        let output = expand(input);
        let output_str = output.to_string();

        // Must contain the CtEq impl
        assert!(output_str.contains("impl simrs_consttime :: CtEq for Mac"), "output: {output_str}");
        // Must contain XOR accumulation
        assert!(output_str.contains("diff |= a [i] ^ b [i]"), "output: {output_str}");
        // Must contain the final comparison
        assert!(output_str.contains("diff == 0"), "output: {output_str}");
    }

    #[test]
    fn named_struct_multiple_fields() {
        let input = quote! {
            struct AuthResult {
                mac: [u8; 8],
                res: [u8; 16],
            }
        };
        let output = expand(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for AuthResult"));
        // Should reference both fields
        assert!(output_str.contains("self . mac"));
        assert!(output_str.contains("self . res"));
    }

    #[test]
    fn tuple_struct_u8_field() {
        let input = quote! {
            struct Byte(u8);
        };
        let output = expand(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for Byte"));
        assert!(output_str.contains("diff |= self . 0 ^ other . 0"), "output: {output_str}");
    }

    #[test]
    fn unit_struct() {
        let input = quote! {
            struct Marker;
        };
        let output = expand(input);
        let output_str = output.to_string();

        assert!(output_str.contains("impl simrs_consttime :: CtEq for Marker"));
        assert!(output_str.contains("diff == 0"));
    }

    #[test]
    fn enum_rejected() {
        let input = quote! {
            enum MyEnum {
                A,
                B,
            }
        };
        let output = expand(input);
        let output_str = output.to_string();

        // Must produce a compile error about enums
        assert!(output_str.contains("compile_error"), "output: {output_str}");
        assert!(output_str.contains("enum"), "output: {output_str}");
    }

    #[test]
    fn mixed_u8_and_array_fields() {
        let input = quote! {
            struct Mixed {
                tag: u8,
                data: [u8; 16],
            }
        };
        let output = expand(input);
        let output_str = output.to_string();

        assert!(output_str.contains("self . tag ^ other . tag"), "output: {output_str}");
        assert!(output_str.contains("self . data"), "output: {output_str}");
    }

    #[test]
    fn multiple_tuple_fields() {
        let input = quote! {
            struct Pair([u8; 4], [u8; 8]);
        };
        let output = expand(input);
        let output_str = output.to_string();

        // Both fields should be compared
        assert!(output_str.contains("self . 0"), "output: {output_str}");
        assert!(output_str.contains("self . 1"), "output: {output_str}");
    }
}
