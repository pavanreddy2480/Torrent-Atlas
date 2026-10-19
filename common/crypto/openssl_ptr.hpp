#pragma once

// std::unique_ptr for OpenSSL objects, e.g. OpenSslPtr<EVP_PKEY, EVP_PKEY_free>.

#include <memory>

template <auto Free>
struct OpenSslFree {
    template <typename T>
    void operator()(T *object) const { Free(object); }
};

template <typename T, auto Free>
using OpenSslPtr = std::unique_ptr<T, OpenSslFree<Free>>;
