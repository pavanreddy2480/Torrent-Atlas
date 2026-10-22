#pragma once

/// @file openssl_ptr.hpp
/// std::unique_ptr for OpenSSL objects, so they are freed automatically.
///
/// Example: OpenSslPtr<EVP_PKEY, EVP_PKEY_free> key(EVP_PKEY_new());

#include <memory>

/// Deleter that calls the OpenSSL free function given as a template argument.
template <auto Free>
struct OpenSslFree {
    template <typename T>
    void operator()(T *object) const { Free(object); }
};

/// A unique_ptr<T> that releases its object with Free (e.g. EVP_PKEY_free).
template <typename T, auto Free>
using OpenSslPtr = std::unique_ptr<T, OpenSslFree<Free>>;
